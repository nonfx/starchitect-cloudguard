import { GetAccountAuthorizationDetailsCommand, IAMClient } from "@aws-sdk/client-iam";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import type { TestResult } from "../../types";
import { CloudProvider } from "./base";

import { logger } from "../logger";

export class AWSProvider extends CloudProvider {
	private iamClient: IAMClient;

	constructor() {
		super();
		this.iamClient = new IAMClient({});
	}

	async detectCredentials(): Promise<boolean> {
		try {
			const sts = new STSClient();
			const identity = await sts.send(new GetCallerIdentityCommand({}));

			// @todo - Provide a more helpful message on how to ensure AWS credentials are set up
			// Either using env variables, or profiles or aws sso CLI
			if (!identity.UserId) {
				throw new Error("AWS credentials not found or invalid");
			}
			return true;
		} catch (error) {
			logger.debug(error);
			throw new Error("AWS credentials not found or invalid");
			return false;
		}
	}

	async validateCredentials(): Promise<boolean> {
		return this.detectCredentials();
	}

	async listAvailableServices(): Promise<string[]> {
		return ["iam", "ec2", "cloudwatch"];
	}

	async runTest(testName: string): Promise<TestResult> {}
}
