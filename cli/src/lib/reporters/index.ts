import { ComplianceStatus, type TestResult } from "../../types.js";

export interface Reporter {
	report(results: TestResult[]): void | Promise<void>;
}

export class ConsoleReporter implements Reporter {
	//@todo - make report format consistent and support different report types (json, html, etc)
	//@todo - Formst reports using https://www.npmjs.com/package/tty-table
	report(results: TestResult[]): void {
		const summary = {
			total: results.length,
			passed: results.filter(r => r.status === ComplianceStatus.PASS).length,
			failed: results.filter(r => r.status === ComplianceStatus.FAIL).length,
			skipped: results.filter(r => r.status === ComplianceStatus.NOTAPPLICABLE).length
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
			console.log(`\n${result.test.title}: ${result.status.toUpperCase()}`);
			if (result.message) {
				console.log(`Message: ${result.message}`);
			}
		});
	}
}

export class JSONReporter implements Reporter {
	report(results: TestResult[]): void {
		console.log(JSON.stringify(results, null, 2));
	}
}
