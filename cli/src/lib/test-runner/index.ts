import {
	ComplianceStatus,
	type RuntimeTest,
	type RuntimeTestMeta,
	type TestResult
} from "../../types.js";
import type { CloudRuntimeProvider } from "../cloud/runtime-provider.js";
import { logger } from "../logger.js";

export class TestRunner {
	async runSingleTest(test: RuntimeTest, provider: CloudRuntimeProvider): Promise<TestResult> {
		const startTime = Date.now();

		const testMeta = { ...test } as unknown as RuntimeTestMeta;

		//@ts-expect-error We know this property is not missing because it comes from the test object
		delete testMeta.execute;

		try {
			logger.debug(`Starting test: ${test.title}`);
			const args = await provider.getTestArguments();
			const result = await test.execute(...args);
			logger.debug(`Completed test: ${test.title}`);

			let status = ComplianceStatus.PASS;

			// Remove duplicate messages
			const messages = Array.from(
				new Set(result.checks.filter(check => Boolean(check.message)).map(check => check.message))
			);

			const message = messages.length > 0 ? messages.join(",") : "All checks passed";

			const hasErrors = result.checks.some(check => check.status === ComplianceStatus.ERROR);
			const hasFailures = result.checks.some(check => check.status === ComplianceStatus.FAIL);
			const allNotApplicable = result.checks.every(
				check => check.status === ComplianceStatus.NOTAPPLICABLE
			);

			// Errors take priority over failures
			if (hasErrors) {
				status = ComplianceStatus.ERROR;
			} else if (hasFailures) {
				status = ComplianceStatus.FAIL;
			} else if (allNotApplicable) {
				status = ComplianceStatus.NOTAPPLICABLE;
			}

			return {
				status,
				message,
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
				status: ComplianceStatus.ERROR,
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
