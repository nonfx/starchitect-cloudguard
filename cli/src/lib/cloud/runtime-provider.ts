import { Command, Flags } from "@oclif/core";
import { ComplianceStatus, type RuntimeTest, type TestResult } from "../../types.js";
import * as cliProgress from "cli-progress";
import PQueue from "p-queue";
import { TestRunner } from "../test-runner/index.js";
import { ConsoleReporter } from "../reporters/console.js";
import { JSONReporter } from "../reporters/json.js";

export abstract class CloudRuntimeProvider extends Command {
	public static enableJsonFlag = true;
	static description = "Run security tests against cloud runtime environments";

	static flags = {
		concurrency: Flags.integer({
			description: "Number of tests to run concurrently",
			default: 5
		}),
		format: Flags.string({
			description: "Output format",
			options: ["json", "stdout"],
			default: "stdout"
		})
	};

	async run(): Promise<void> {
		const { flags } = await this.parse(this.getConstructor());

		// Validate credentials for selected provider
		try {
			await this.validateCredentials();
		} catch (error) {
			this.error(error as Error, { exit: 1 });
		}

		// Gather arguments from the user
		await this.gatherTestArguments();

		const progressBar = new cliProgress.SingleBar(
			{
				format: "Running tests [{bar}] {percentage}% | ETA: {eta}s | {value}/{total}",
				autopadding: true,
				forceRedraw: true,
				clearOnComplete: true
			},
			cliProgress.Presets.shades_grey
		);

		let testPassed = true;

		try {
			const runner = new TestRunner();
			const tests = await this.getTests();

			if (tests.length === 0) {
				this.error("No tests selected.", { exit: 1 });
			}

			progressBar.start(tests.length, 0);

			const queue = new PQueue({ concurrency: flags.concurrency });
			const results: TestResult[] = [];
			let completed = 0;

			await queue.addAll(
				tests.map(test => async () => {
					const result = await runner.runSingleTest(test, this);
					progressBar.update(++completed);
					results.push(result);
				})
			);

			progressBar.stop();

			const reporter = flags.format === "json" ? new JSONReporter() : new ConsoleReporter();
			reporter.report(results);

			if (
				results.some(r => r.status === ComplianceStatus.FAIL || r.status === ComplianceStatus.ERROR)
			) {
				testPassed = false;
			}
		} catch (error) {
			progressBar.stop();
			this.debug(error);
			await this.onTestCompletion(false);
			this.error(
				"Test execution failed. Please log an issue at https://github.com/nonfx/starchitect-cloudguard/issues/new",
				{ exit: 1 }
			);
		}

		await this.onTestCompletion(!testPassed);

		if (!testPassed && flags.format !== "json") {
			this.error("Some tests failed.", { exit: 1 });
		}
	}

	abstract getConstructor(): typeof CloudRuntimeProvider;
	abstract detectCredentials(): Promise<boolean>;
	abstract validateCredentials(): Promise<boolean>;
	abstract getTests(): Promise<RuntimeTest[]>;
	abstract getTestArguments(): Promise<unknown[]>;
	abstract gatherTestArguments(): Promise<void>;

	// eslint-disable-next-line @typescript-eslint/no-unused-vars
	async onTestCompletion(_status: boolean): Promise<void> {
		// do nothing
	}
}
