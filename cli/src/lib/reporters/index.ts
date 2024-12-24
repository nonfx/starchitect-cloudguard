import type { TestResult } from "../../types";

export interface Reporter {
	report(results: TestResult[]): void | Promise<void>;
}

export class ConsoleReporter implements Reporter {
	report(results: TestResult[]): void {
		const summary = {
			total: results.length,
			passed: results.filter(r => r.status === "passed").length,
			failed: results.filter(r => r.status === "failed").length,
			skipped: results.filter(r => r.status === "skipped").length
		};

		console.log("\nTest Results Summary:");
		console.log("--------------------");
		console.log(`Total: ${summary.total}`);
		console.log(`Passed: ${summary.passed}`);
		console.log(`Failed: ${summary.failed}`);
		console.log(`Skipped: ${summary.skipped}`);
		console.log("\nDetailed Results:");
		console.log("----------------");

		results.forEach(result => {
			console.log(`\n${result.name}: ${result.status.toUpperCase()}`);
			if (result.message) {
				console.log(`Message: ${result.message}`);
			}
			if (result.details) {
				console.log("Details:", result.details);
			}
		});
	}
}

export class JSONReporter implements Reporter {
	report(results: TestResult[]): void {
		console.log(JSON.stringify(results, null, 2));
	}
}
