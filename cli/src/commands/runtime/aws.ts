import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { EC2Client, DescribeRegionsCommand } from "@aws-sdk/client-ec2";
import allTests from "../../../../runtime/aws/index.js";
import inquirer from "inquirer";
import { Flags } from "@oclif/core";
import { CloudProvider } from "../../lib/cloud/base.js";
import type { RuntimeTest } from "../../types.js";
import { generatePrefilledCommand } from "../../lib/utils.js";

const allServices = Object.values(
	(allTests as RuntimeTest[]).reduce(
		(out, test) => {
			out[test.shortServiceName] = { name: test.serviceName, shortName: test.shortServiceName };
			return out;
		},
		{} as Record<string, { name: string; shortName: string }>
	)
);

export class AWSProvider extends CloudProvider {
	static description = "Run security tests against your AWS runtime environment";

	static flags = {
		...CloudProvider.flags,
		services: Flags.string({
			description: "Comma separated list of cloud services to test"
		}),
		profile: Flags.string({
			description: "Cloud provider profile to use"
		}),
		region: Flags.string({
			description: "Region to test"
		})
	};

	region?: string;
	services?: string[];

	getConstructor(): typeof CloudProvider {
		return AWSProvider;
	}

	async detectCredentials(): Promise<boolean> {
		try {
			const sts = new STSClient();
			const identity = await sts.send(new GetCallerIdentityCommand({}));

			// @todo - Provide a more helpful message on how to ensure AWS credentials are set up
			// Either using env variables, or profiles or aws sso CLI
			// Use inquirer to give the users an option to choose then restart the CLI
			if (!identity.UserId) {
				this.error("AWS credentials not found or invalid", { exit: 1 });
			}
			return true;
		} catch (error) {
			this.debug(error);
			this.error("AWS credentials not found or invalid", { exit: 1 });
		}
	}

	async validateCredentials(): Promise<boolean> {
		return this.detectCredentials();
	}

	async getTests() {
		return (allTests as RuntimeTest[]).filter(test =>
			this.services?.includes(test.shortServiceName)
		);
	}

	async gatherTestArguments() {
		const { flags } = await this.parse(AWSProvider);

		if (flags.region) {
			this.region = flags.region;
		}

		// Throw an error if the region is not provided and the process is running in a CI environment
		if (!this.region) {
			if (process.env.CI) {
				this.error("AWS region not provided, Please set the region using the --region flag", {
					exit: 1
				});
			}

			try {
				const ec2Client = new EC2Client();
				const command = new DescribeRegionsCommand({});
				const response = await ec2Client.send(command);
				const regionsList = response.Regions?.map(region => region.RegionName || "") || [];

				if (regionsList.length === 0) {
					this.error("No regions found", { exit: 1 });
				}

				const userSelectedRegion = await inquirer.prompt([
					{
						type: "list",
						name: "value",
						message: "Select your AWS region:",
						choices: regionsList
					}
				]);

				this.region = String(userSelectedRegion.value);
			} catch (error) {
				this.debug(error);
				this.error("Failed to fetch AWS regions.", { exit: 1 });
			}
		}

		if (flags.services) {
			this.services = flags.services.split(",").map(service => service.trim());
		}

		// If no services are provided and the process is running in a CI environment, assume we are running it for all
		if (!this.services) {
			if (process.env.CI) {
				this.services = allServices.map(service => service.shortName);
			} else {
				const userSelectedServices = await inquirer.prompt([
					{
						type: "checkbox",
						name: "value",
						message: "Select services:",
						choices: allServices.map(service => ({
							value: service.name,
							checked: true
						}))
					}
				]);

				const selectedServices = userSelectedServices.value as string[];

				this.services = allServices
					.filter(service => selectedServices.includes(service.name))
					.map(service => service.shortName);
			}
		}
	}

	async getTestArguments() {
		return [this.region];
	}

	async onTestCompletion() {
		const { flags } = await this.parse(AWSProvider);

		// If the output format is JSON, don't show the command
		if (flags.format === "json") {
			return;
		}

		flags.region = this.region;
		flags.services = this.services?.join(",") || "";

		const command = generatePrefilledCommand("runtime aws", flags);

		this.log(
			`\n\nTo run the same test again, you can use the following command: \n> ${command}\n\n`
		);
	}
}
