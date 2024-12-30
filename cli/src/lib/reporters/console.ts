import { ComplianceStatus, type TestResult } from "../../types.js";
import chalk from "chalk";
import type { Reporter } from "./index.js";

export class ConsoleReporter implements Reporter {
	report(results: TestResult[]): void {
		const groupedResults = {
			failed: results.filter(r => r.status === ComplianceStatus.FAIL),
			passed: results.filter(r => r.status === ComplianceStatus.PASS),
			skipped: results.filter(r => r.status === ComplianceStatus.NOTAPPLICABLE)
		};

		console.log("\n" + chalk.bold.cyan("Security Test Results"));
		console.log(chalk.gray("=".repeat(50)));

		// Failed Tests Section
		if (groupedResults.failed.length > 0) {
			console.log("\n" + chalk.red.bold("Failed Tests"));
			console.log(chalk.gray("-".repeat(30)));
			this.printResultGroup(groupedResults.failed);
		}

		// Passed Tests Section
		if (groupedResults.passed.length > 0) {
			console.log("\n" + chalk.green.bold("Passed Tests"));
			console.log(chalk.gray("-".repeat(30)));
			this.printResultGroup(groupedResults.passed);
		}

		// Skipped Tests Section
		if (groupedResults.skipped.length > 0) {
			console.log("\n" + chalk.yellow.bold("Skipped Tests"));
			console.log(chalk.gray("-".repeat(30)));
			this.printResultGroup(groupedResults.skipped);
		}

		// Summary Section
		const summary = {
			total: results.length,
			passed: groupedResults.passed.length,
			failed: groupedResults.failed.length,
			skipped: groupedResults.skipped.length
		};

		console.log("\n" + chalk.bold.cyan("Summary"));
		console.log(chalk.gray("=".repeat(50)));
		console.log(`Total Tests: ${chalk.bold(summary.total)}`);
		console.log(
			`${chalk.green("✓")} Passed: ${chalk.green.bold(summary.passed)} (${((summary.passed / summary.total) * 100).toFixed(1)}%)`
		);
		console.log(
			`${chalk.red("✗")} Failed: ${chalk.red.bold(summary.failed)} (${((summary.failed / summary.total) * 100).toFixed(1)}%)`
		);
		console.log(
			`${chalk.yellow("⚠")} Skipped: ${chalk.yellow.bold(summary.skipped)} (${((summary.skipped / summary.total) * 100).toFixed(1)}%)\n`
		);
	}

	private printResultGroup(results: TestResult[]): void {
		results.forEach(result => {
			const statusIcon = this.getStatusIcon(result.status);

			console.log(`\n${statusIcon} ${chalk.bold(result.test.title)}`);
			if (result.message) {
				console.log(chalk.dim(`   Message: ${result.message}`));
			}
			if (result.test.severity) {
				const severityColor = this.getSeverityColor(result.test.severity);
				console.log(`   ${severityColor(`Severity: ${result.test.severity}`)}`);
			}
			if (result.test.serviceName) {
				console.log(chalk.dim(`   Service: ${result.test.serviceName}`));
			}
		});
	}

	private getStatusIcon(status: ComplianceStatus): string {
		switch (status) {
			case ComplianceStatus.PASS:
				return chalk.green("✓");
			case ComplianceStatus.FAIL:
				return chalk.red("✗");
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
