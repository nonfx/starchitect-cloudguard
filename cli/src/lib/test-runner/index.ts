import type { RuntimeTest, RuntimeTestMeta, TestResult } from "../../types";
import { CloudProvider } from "../cloud/base";
import { logger } from "../logger";

export class TestRunner {
	constructor(private provider: CloudProvider) {}

	async runTests(tests: RuntimeTest[], parallel = true): Promise<TestResult[]> {
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

	async runSingleTest(test: RuntimeTest): Promise<TestResult> {
		const startTime = Date.now();

		const testMeta = { ...test } as unknown as RuntimeTestMeta;

		//@ts-expect-error We know this property is not missing because it comes from the test object
		delete testMeta.execute;

		try {
			logger.debug(`Starting test: ${test.title}`);
			const result = await test.execute();
			logger.debug(`Completed test: ${test.title}`);

			return {
				timestamp: Date.now(),
				test: testMeta,
				duration: Date.now() - startTime,
				checks: result
			};
		} catch (error) {
			logger.error(`Test failed: ${test.title}`);

			//@todo - Use https://www.npmjs.com/package/terminal-link for linking to the right issue
			//@todo - Ideally prefill the error message in the issue body
			return {
				message:
					error instanceof Error
						? error.message
						: "Test failed to run. Please log an issue at https://github.com/nonfx/starchitect-cloudguard/issues/new",
				timestamp: Date.now(),
				test: testMeta,
				duration: Date.now() - startTime,
				checks: {
					checks: []
				}
			};
		}
	}
}
