import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { EC2Client, DescribeRegionsCommand } from "@aws-sdk/client-ec2";
import allTests from "../../../../../runtime/aws/index.js";
import inquirer from "inquirer";
import { Flags } from "@oclif/core";
import { CloudProvider } from "../../../lib/cloud/base.js";
import type { RuntimeTest } from "../../../types.js";

export class AWSProvider extends CloudProvider {
	static flags = {
		...CloudProvider.flags,
		services: Flags.string({
			char: "s",
			description: "Specific services to test"
		}),
		profile: Flags.string({
			description: "Cloud provider profile to use"
		}),
		region: Flags.string({
			char: "r",
			description: "Region to test"
		})
	};

	region?: string;

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
				throw new Error("AWS credentials not found or invalid");
			}
			return true;
		} catch (error) {
			this.debug(error);
			throw new Error("AWS credentials not found or invalid");
		}
	}

	async validateCredentials(): Promise<boolean> {
		return this.detectCredentials();
	}

	async getTests() {
		return allTests as RuntimeTest[];
	}

	async gatherTestArguments() {
		//@todo - check for flags first
		//@todo check for CI and fail if not provided

		// if (currentValue || process.env.CI) {
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
					message: "Select region:",
					choices: regionsList
				}
			]);

			this.region = String(userSelectedRegion.value);
		} catch (error) {
			this.debug(error);
			throw new Error("Failed to fetch AWS regions");
		}
	}

	async getTestArguments() {
		return [this.region];
	}
}
