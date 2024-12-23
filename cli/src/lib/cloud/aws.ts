import { CloudProvider } from "./base.js";
import { TestResult } from "../../types/index.js";
import {
	IAMClient,
	GetAccountAuthorizationDetailsCommand,
	ListUsersCommand
} from "@aws-sdk/client-iam";
import { logger } from "../logger.js";

export class AWSProvider extends CloudProvider {
	private iamClient: IAMClient;

	constructor() {
		super();
		this.iamClient = new IAMClient({});
	}

	async detectCredentials(): Promise<boolean> {
		try {
			await this.iamClient.send(new ListUsersCommand({}));
			return true;
		} catch (error) {
			console.error(error);
			logger.debug("AWS credentials not found or invalid");
			return false;
		}
	}

	async validateCredentials(): Promise<boolean> {
		return this.detectCredentials();
	}

	async listAvailableServices(): Promise<string[]> {
		return ["iam", "ec2", "cloudwatch"];
	}

	async runTest(testName: string): Promise<TestResult> {
		const startTime = Date.now();

		try {
			switch (testName) {
				case "iam-root-access-keys":
					return await this.testRootAccessKeys();
				default:
					throw new Error(`Unknown test: ${testName}`);
			}
		} catch (error) {
			return {
				name: testName,
				status: "failed",
				message: error instanceof Error ? error.message : "Unknown error",
				timestamp: new Date().toISOString(),
				duration: Date.now() - startTime
			};
		}
	}

	private async testRootAccessKeys(): Promise<TestResult> {
		const startTime = Date.now();

		try {
			const command = new GetAccountAuthorizationDetailsCommand({});
			const response = await this.iamClient.send(command);

			console.warn(response.UserDetailList);

			const rootUserAccessKeys =
				//@ts-expect-error sdsdassdasd
				response.UserDetailList?.find(user => user.Arn?.includes(":root"))?.AccessKeys?.length ?? 0;

			return {
				name: "iam-root-access-keys",
				status: rootUserAccessKeys === 0 ? "passed" : "failed",
				message:
					rootUserAccessKeys === 0
						? "No root access keys found"
						: "Root account has access keys configured",
				details: { rootUserAccessKeys },
				timestamp: new Date().toISOString(),
				duration: Date.now() - startTime
			};
		} catch (error) {
			throw error;
		}
	}
}
