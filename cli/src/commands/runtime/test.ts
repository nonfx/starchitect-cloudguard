import { Command, Flags } from "@oclif/core";
import * as cliProgress from "cli-progress";
import inquirer from "inquirer";
import { AWSProvider } from "../../lib/cloud/aws";
import { logger } from "../../lib/logger";
import { ConsoleReporter, JSONReporter } from "../../lib/reporters";
import { TestRunner } from "../../lib/test-runner";
import { ComplianceStatus } from "~runtime/types";

export default class RuntimeTestRunner extends Command {
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

		const progressBar = new cliProgress.SingleBar({}, cliProgress.Presets.shades_classic);

		if (flags.cloud !== "aws") {
			// @todo - Offer a link to issues so that the user can request support for other cloud providers
			logger.error("Only AWS is supported at the moment");
			return;
		}

		try {
			// @todo - Each provider should ask it's own questions
			const provider = new AWSProvider();

			try {
				await provider.validateCredentials();
			} catch (error) {
				logger.error(error);
				return;
			}

			// const tests = iamTests;
			const runner = new TestRunner();

			const tests = await provider.getTests();

			progressBar.start(tests.length, 0);
			let completed = 0;

			const results = await Promise.all(
				tests.map(async test => {
					//@todo - use PQueue to limit the number of concurrent tests
					//@todo - Read the number of concurrent tests from the user provided config
					// @todo - use parallel test run ability with callbacks
					const result = await runner.runSingleTest(test, provider);
					progressBar.update(++completed);
					return result;
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
			logger.error("Test execution failed:", error);
			this.error(error instanceof Error ? error.message : "An unknown error occurred");
		}
	}
}
