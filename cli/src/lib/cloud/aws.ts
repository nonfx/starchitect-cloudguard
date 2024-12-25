import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import type { RuntimeTest } from "~runtime/types";
import allTests from "../../../../runtime/aws";
import { logger } from "../logger";
import { CloudProvider } from "./base";

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

	async getTests(): Promise<RuntimeTest[]> {
		return allTests;
	}

	//@todo - Get the list of regions from the AWS SDK
	//@todo - Use inquirer to prompt the user to select a region and use that value
	async getTestArguments() {
		return ["ap-southeast-1"];
	}
}
