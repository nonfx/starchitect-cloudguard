import { Command, Flags } from "@oclif/core";
import * as cliProgress from "cli-progress";
import inquirer from "inquirer";
import PQueue from "p-queue";
import { ComplianceStatus } from "~runtime/types";
import { AWSProvider } from "../../lib/cloud/aws";
import { ConsoleReporter, JSONReporter } from "../../lib/reporters";
import { TestRunner } from "../../lib/test-runner";
import type { TestResult } from "../../types";

export default class RuntimeTestRunner extends Command {
	public static enableJsonFlag = true;

	static description = "Run security tests against cloud runtime environments";

	static flags = {
		cloud: Flags.string({
			char: "c",
			description: "Cloud provider to test",
			options: ["aws", "azure", "gcp"]
		}),
		service: Flags.string({
			char: "s",
			description: "Specific service to test"
		}),
		profile: Flags.string({
			description: "Cloud provider profile to use"
		}),
		region: Flags.string({
			description: "Region to test"
		}),
		parallel: Flags.boolean({
			description: "Run tests in parallel",
			default: true
		}),
		concurrency: Flags.integer({
			description: "Number of tests to run concurrently",
			default: 5
		}),
		format: Flags.string({
			description: "Output format",
			options: ["json", "stdout", "html"],
			default: "stdout"
		})
	};

	async run(): Promise<void> {
		const { flags } = await this.parse(RuntimeTestRunner);

		if (!flags.cloud && !process.env.CI) {
			const response = await inquirer.prompt([
				{
					type: "list",
					name: "cloud",
					message: "Select cloud provider:",
					choices: ["AWS", "Azure", "GCP"]
				}
			]);
			flags.cloud = response.cloud.toLowerCase();
		}

		if (flags.cloud !== "aws") {
			// @todo - Offer a link to issues so that the user can request support for other cloud providers
			this.error("Only AWS is supported at the moment", { exit: 1 });
		}

		const progressBar = new cliProgress.SingleBar(
			{
				format: "Running tests [{bar}] {percentage}% | ETA: {eta}s | {value}/{total}",
				autopadding: true,
				forceRedraw: true,
				clearOnComplete: true
			},
			cliProgress.Presets.shades_grey
		);

		try {
			// @todo - Each provider should ask it's own questions
			const provider = new AWSProvider();

			try {
				await provider.validateCredentials();
			} catch (error) {
				this.error(error as Error, { exit: 1 });
			}

			const runner = new TestRunner();

			const tests = await provider.getTests();

			progressBar.start(tests.length, 0);

			const queue = new PQueue({ concurrency: flags.concurrency });
			const results: TestResult[] = [];
			let completed = 0;

			await queue.addAll(
				tests.map(test => async () => {
					const result = await runner.runSingleTest(test, provider);
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
				this.exit(1);
			}
		} catch (error) {
			progressBar.stop();
			console.error(error);
			this.error(
				"Test execution failed. Please log an issue at https://github.com/nonfx/starchitect-cloudguard/issues/new",
				{ exit: 1 }
			);
		}
	}
}
