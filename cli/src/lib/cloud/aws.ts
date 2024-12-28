import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { EC2Client, DescribeRegionsCommand } from "@aws-sdk/client-ec2";
import allTests from "../../../../runtime/aws/index.js";
import { logger } from "../logger.js";
import { CloudProvider } from "./base.js";
import type { RuntimeTest } from "../../types.js";

export class AWSProvider extends CloudProvider {
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
			logger.debug(error);
			throw new Error("AWS credentials not found or invalid");
		}
	}

	async validateCredentials(): Promise<boolean> {
		return this.detectCredentials();
	}

	async getTests() {
		return allTests as RuntimeTest[];
	}

	async getRegions(): Promise<string[]> {
		try {
			const ec2Client = new EC2Client();
			const command = new DescribeRegionsCommand({});
			const response = await ec2Client.send(command);
			return response.Regions?.map(region => region.RegionName || "") || [];
		} catch (error) {
			logger.debug(error);
			throw new Error("Failed to fetch AWS regions");
		}
	}

	async getTestArguments() {
		const regions = await this.getRegions();
		return [regions[0]]; // Default to first region
	}
}
