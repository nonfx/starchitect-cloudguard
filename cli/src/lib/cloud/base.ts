import type { TestResult } from "../../types";

export abstract class CloudProvider {
	abstract detectCredentials(): Promise<boolean>;
	abstract validateCredentials(): Promise<boolean>;
	abstract listAvailableServices(): Promise<string[]>;
	abstract runTest(testName: string): Promise<TestResult>;

	protected async handleError(error: Error): Promise<never> {
		throw new CloudGuardError(
			error.message,
			"CLOUD_PROVIDER_ERROR",
			"ERROR",
			"Please check your credentials and try again"
		);
	}
}

export class CloudGuardError extends Error {
	constructor(
		message: string,
		public code: string,
		public severity: "ERROR" | "WARNING",
		public suggestion?: string
	) {
		super(message);
		this.name = "CloudGuardError";
	}
}
