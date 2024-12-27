import { Command, Flags } from "@oclif/core";
import * as cliProgress from "cli-progress";
import inquirer from "inquirer";
import PQueue from "p-queue";
import { ComplianceStatus } from "~runtime/types";
import { AWSProvider } from "../../lib/cloud/aws";
import { CloudProvider } from "../../lib/cloud/base";
import { ConsoleReporter, JSONReporter } from "../../lib/reporters";
import { TestRunner } from "../../lib/test-runner";
import type { TestResult } from "../../types";

const SUPPORTED_CLOUDS = ["aws", "azure", "gcp"];

export default class RuntimeTestRunner extends Command {
	public static enableJsonFlag = true;
	static description = "Run security tests against cloud runtime environments";

	static flags = {
		cloud: Flags.string({
			char: "c",
			description: "Cloud provider to test"
		}),
		service: Flags.string({
			char: "s",
			description: "Specific service to test"
		}),
		profile: Flags.string({
			description: "Cloud provider profile to use"
		}),
		region: Flags.string({
			char: "r",
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

		// Get cloud provider selection
		flags.cloud = await this.promptForSelection(
			flags.cloud,
			"Select cloud provider:",
			SUPPORTED_CLOUDS
		);

		let provider: CloudProvider;
		switch (flags.cloud) {
			case "aws":
				provider = new AWSProvider();
				break;
			default:
				this.error("Only AWS is supported at the moment", { exit: 1 });
		}

		// Validate credentials for selected provider
		try {
			await provider.validateCredentials();
		} catch (error) {
			this.error(error as Error, { exit: 1 });
		}

		// Get region selection
		const regions = await provider.getRegions();
		flags.region = await this.promptForSelection(flags.region, "Select region:", regions);

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

	private async promptForSelection(
		currentValue: string | undefined,
		message: string,
		choices: readonly string[] | string[]
	): Promise<string> {
		if (currentValue || process.env.CI) {
			return currentValue?.toLowerCase() ?? "";
		}

		const response = await inquirer.prompt([
			{
				type: "list",
				name: "value",
				message,
				choices
			}
		]);

		return response.value.toLowerCase();
	}
}
