import { Command, Flags } from "@oclif/core";
import * as cliProgress from "cli-progress";
import inquirer from "inquirer";
import { AWSProvider } from "../../lib/cloud/aws";
import { logger } from "../../lib/logger";
import { ConsoleReporter, JSONReporter } from "../../lib/reporters";
import { TestRunner } from "../../lib/test-runner";

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

		try {
			const provider = new AWSProvider();

			try {
				await provider.validateCredentials();
			} catch (error) {
				logger.error(error);
				return;
			}

			// const tests = iamTests;
			// const runner = new TestRunner(provider);

			// progressBar.start(tests.length, 0);
			// let completed = 0;

			// const results = await Promise.all(
			// 	tests.map(async test => {
			// 		const result = await runner.runSingleTest(test);
			// 		progressBar.update(++completed);
			// 		return result;
			// 	})
			// );

			// progressBar.stop();

			// const reporter = flags.format === "json" ? new JSONReporter() : new ConsoleReporter();

			// reporter.report(results);

			// if (results.some(r => r.status === "failed")) {
			// 	this.exit(1);
			// }
		} catch (error) {
			progressBar.stop();
			logger.error("Test execution failed:", error);
			this.error(error instanceof Error ? error.message : "An unknown error occurred");
		}
	}
}
