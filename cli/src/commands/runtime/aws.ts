import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { EC2Client, DescribeRegionsCommand } from "@aws-sdk/client-ec2";
import allTests from "../../../../runtime/aws/index.js";
import inquirer from "inquirer";
import { Flags } from "@oclif/core";
import { CloudRuntimeProvider } from "../../lib/cloud/runtime-provider.js";
import type { RuntimeTest } from "../../types.js";
import { generatePrefilledCommand } from "../../lib/utils.js";
import chalk from "chalk";

const allServices = Object.values(
	(allTests as RuntimeTest[]).reduce(
		(out, test) => {
			out[test.shortServiceName] = { name: test.serviceName, shortName: test.shortServiceName };
			return out;
		},
		{} as Record<string, { name: string; shortName: string }>
	)
);

export class AWSProvider extends CloudRuntimeProvider {
	static description = "Run security tests against your AWS runtime environment";

	static flags = {
		...CloudRuntimeProvider.flags,
		services: Flags.string({
			description:
				"Comma separated list of cloud services to test. Pass 'all' to test all services",
			multiple: true,
			delimiter: ",",
			options: ["all", ...allServices.map(service => service.shortName)]
		}),
		region: Flags.string({
			description: "Region to test"
		})
	};

	region?: string;
	services?: string[];

	getConstructor(): typeof CloudRuntimeProvider {
		return AWSProvider;
	}

	async detectCredentials(): Promise<boolean> {
		try {
			const sts = new STSClient();
			const identity = await sts.send(new GetCallerIdentityCommand({}));

			if (!identity.UserId) {
				this.showCredentialsHelp();
				this.exit(1);
			}
			return true;
		} catch (error) {
			this.debug(error);
			this.showCredentialsHelp();
			this.exit(1);
		}
	}

	private showCredentialsHelp(): void {
		const message = `
${chalk.red.bold("✗ AWS Credentials Not Found")}
${chalk.gray("=")}${chalk.gray("=".repeat(40))}

${chalk.yellow("starkit needs valid AWS credentials to run security tests.")}
Here are two ways to configure your AWS credentials:

${chalk.cyan.bold("1. Using Environment Variables")}
   Export these variables in your terminal:

   ${chalk.gray("export")} ${chalk.green("AWS_ACCESS_KEY_ID")}=${chalk.yellow("<your-access-key>")}
   ${chalk.gray("export")} ${chalk.green("AWS_SECRET_ACCESS_KEY")}=${chalk.yellow("<your-secret-key>")}

${chalk.cyan.bold("2. Using AWS CLI (Recommended)")}
   First, install the AWS CLI from: ${chalk.blue.underline("https://aws.amazon.com/cli/")}
   Then, run:

   ${chalk.gray("$")} ${chalk.white("aws configure")}
   ${chalk.dim("AWS Access Key ID:")} ${chalk.yellow("[your-access-key]")}
   ${chalk.dim("AWS Secret Access Key:")} ${chalk.yellow("[your-secret-key]")}
   ${chalk.dim("Default region name:")} ${chalk.yellow("[your-region]")}
   ${chalk.dim("Default output format:")} ${chalk.yellow("[json]")}

${chalk.cyan.bold("Need Help?")}
• Create access keys: ${chalk.blue.underline("https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html")}
• AWS CLI setup guide: ${chalk.blue.underline("https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html")}
`;

		this.log(message);
	}

	async validateCredentials(): Promise<boolean> {
		return this.detectCredentials();
	}

	async getTests() {
		if (this.services?.includes("all")) {
			return allTests as RuntimeTest[];
		}

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
						message: "Select your AWS region (Use your arrows keys to scroll):",
						choices: regionsList,
						pageSize: 10
					}
				]);

				this.region = String(userSelectedRegion.value);
			} catch (error) {
				this.debug(error);
				this.error(
					"Failed to fetch AWS regions. Please check if you have enough permissions. For detailed error message run this command with DEBUG='*' environment variable.",
					{ exit: 1 }
				);
			}
		}

		if (flags.services) {
			this.services = flags.services.map(service => service.trim());
		}

		// If no services are provided and the process is running in a CI environment, assume we are running it for all
		if (!this.services) {
			if (process.env.CI) {
				this.services = allServices.map(service => service.shortName);
			} else {
				const userSelectedServices = await inquirer.prompt([
					{
						type: "confirm",
						message: "Do you want to scan all available services?",
						name: "scanAll"
					},
					{
						type: "checkbox",
						name: "services",
						message: "Select services:",
						choices: allServices.map(service => ({
							value: service.name,
							checked: false
						})),
						pageSize: 10,
						required: true,
						when(answers): boolean {
							return !answers.scanAll;
						}
					}
				]);

				if (userSelectedServices.scanAll) {
					this.services = allServices.map(service => service.shortName);
				} else {
					const selectedServices = userSelectedServices.services as string[];

					if (selectedServices.length === 0) {
						this.error("No services selected", { exit: 1 });
					}

					this.services = allServices
						.filter(service => selectedServices.includes(service.name))
						.map(service => service.shortName);
				}
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
		flags.services = this.services || [];

		const command = generatePrefilledCommand("runtime aws", flags);

		this.log(
			`\n\nTo run the same test again, you can use the following command: \n> ${command}\n\n`
		);
	}
}
