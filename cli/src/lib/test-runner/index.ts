import { TestResult, Test } from "../../types/index.js";
import { CloudProvider } from "../cloud/base.js";
import { logger } from "../logger.js";

export class TestRunner {
	constructor(private provider: CloudProvider) {}

	async runTests(tests: Test[], parallel = true): Promise<TestResult[]> {
		logger.info(`Running ${tests.length} tests${parallel ? " in parallel" : " sequentially"}`);

		if (parallel) {
			return Promise.all(tests.map(test => this.runSingleTest(test)));
		}

		const results: TestResult[] = [];
		for (const test of tests) {
			results.push(await this.runSingleTest(test));
		}
		return results;
	}

	async runSingleTest(test: Test): Promise<TestResult> {
		const startTime = Date.now();

		try {
			logger.debug(`Starting test: ${test.name}`);
			const result = await test.execute();
			logger.debug(`Completed test: ${test.name}`);

			return {
				...result,
				duration: Date.now() - startTime
			};
		} catch (error) {
			logger.error(`Test failed: ${test.name}`);
			return {
				name: test.name,
				status: "failed",
				message: error instanceof Error ? error.message : "Unknown error",
				timestamp: new Date().toISOString(),
				duration: Date.now() - startTime
			};
		}
	}
}
