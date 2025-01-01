import type { TestResult } from "../../types.js";

export interface Reporter {
	report(results: TestResult[]): void | Promise<void>;
}
