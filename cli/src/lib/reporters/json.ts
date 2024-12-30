import { type TestResult } from "../../types.js";
import type { Reporter } from "./index.js";

export class JSONReporter implements Reporter {
	report(results: TestResult[]): void {
		console.log(JSON.stringify(results, null, 2));
	}
}
