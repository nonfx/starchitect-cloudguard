import { ComplianceStatus, type TestResult } from "../../types.js";
import chalk from "chalk";
import type { Reporter } from "./index.js";

export class ConsoleReporter implements Reporter {
	report(results: TestResult[]): void {
		const groupedResults = {
			failed: results.filter(r => r.status === ComplianceStatus.FAIL),
			passed: results.filter(r => r.status === ComplianceStatus.PASS),
			skipped: results.filter(r => r.status === ComplianceStatus.NOTAPPLICABLE),
			error: results.filter(r => r.status === ComplianceStatus.ERROR)
		};

		console.log("\n" + chalk.bold.cyan("Security Test Results"));
		console.log(chalk.gray("=".repeat(50)));

		// Skipped Tests Section
		if (groupedResults.skipped.length > 0) {
			console.log("\n" + chalk.yellow.bold("Skipped Tests"));
			console.log(chalk.gray("-".repeat(30)));
			this.printResultGroup(groupedResults.skipped);
		}

		// Passed Tests Section
		if (groupedResults.passed.length > 0) {
			console.log("\n" + chalk.green.bold("Passed Tests"));
			console.log(chalk.gray("-".repeat(30)));
			this.printResultGroup(groupedResults.passed);
		}

		// Errored Tests Section
		if (groupedResults.error.length > 0) {
			console.log("\n" + chalk.red.bold("Errored Tests"));
			console.log(chalk.gray("-".repeat(30)));
			this.printResultGroup(groupedResults.error);
		}

		// Failed Tests Section
		if (groupedResults.failed.length > 0) {
			console.log("\n" + chalk.red.bold("Failed Tests"));
			console.log(chalk.gray("-".repeat(30)));
			this.printResultGroup(groupedResults.failed);
		}

		// Summary Section
		const summary = {
			total: results.length,
			passed: groupedResults.passed.length,
			failed: groupedResults.failed.length,
			skipped: groupedResults.skipped.length,
			error: groupedResults.error.length
		};

		console.log("\n" + chalk.bold.cyan("Summary"));
		console.log(chalk.gray("=".repeat(50)));
		console.log(`Total Tests: ${chalk.bold(summary.total)}`);
		console.log(
			`${chalk.yellow("⚠")} Skipped: ${chalk.yellow.bold(summary.skipped)} (${((summary.skipped / summary.total) * 100).toFixed(1)}%)`
		);
		console.log(
			`${chalk.green("✓")} Passed: ${chalk.green.bold(summary.passed)} (${((summary.passed / summary.total) * 100).toFixed(1)}%)`
		);
		console.log(
			`${chalk.yellow("✗")} Errored: ${chalk.yellow.bold(summary.error)} (${((summary.error / summary.total) * 100).toFixed(1)}%)`
		);
		console.log(
			`${chalk.red("✗")} Failed: ${chalk.red.bold(summary.failed)} (${((summary.failed / summary.total) * 100).toFixed(1)}%)\n`
		);
	}

	private printResultGroup(results: TestResult[]): void {
		results.forEach(result => {
			const statusIcon = this.getStatusIcon(result.status);

			// Test title and main info
			console.log(`\n${statusIcon} ${chalk.italic(result.test.title)}`);
			if (result.message) {
				console.log(`${chalk.dim(`   Message:`)} ${chalk.bold(result.message)}`);
			}
			if (result.test.severity) {
				const severityColor = this.getSeverityColor(result.test.severity);
				console.log(`${chalk.dim(`   Severity:`)} ${severityColor(`${result.test.severity}`)}`);
			}
			if (result.test.serviceName) {
				console.log(chalk.dim(`   Service: ${result.test.serviceName}`));
			}

			// Detailed check results
			if (result.checks?.checks?.length > 0) {
				console.log(chalk.dim(`   Detailed Results:`));
				result.checks.checks.forEach(check => {
					const checkIcon = this.getStatusIcon(check.status);
					console.log(`     ${checkIcon} ${check.resourceName}`);
					if (check.resourceArn) {
						console.log(chalk.dim(`       ARN: ${check.resourceArn}`));
					}
					if (check.message) {
						const messageColor =
							check.status === ComplianceStatus.PASS ? chalk.green : chalk.yellow;
						console.log(messageColor(`       → ${check.message}`));
					}
				});
			}

			// Add a separator line between tests
			console.log(chalk.dim("   " + "-".repeat(40)));
		});
	}

	private getStatusIcon(status: ComplianceStatus): string {
		switch (status) {
			case ComplianceStatus.PASS:
				return chalk.green("✓");
			case ComplianceStatus.FAIL:
				return chalk.red("✗");
			case ComplianceStatus.ERROR:
				return chalk.yellow("✗");
			case ComplianceStatus.NOTAPPLICABLE:
				return chalk.yellow("⚠");
			default:
				return chalk.gray("•");
		}
	}

	private getSeverityColor(severity: string) {
		switch (severity.toUpperCase()) {
			case "HIGH":
				return chalk.red;
			case "MEDIUM":
				return chalk.yellow;
			case "LOW":
				return chalk.blue;
			default:
				return chalk.gray;
		}
	}
}
