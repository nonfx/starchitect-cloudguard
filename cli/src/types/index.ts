export interface TestResult {
	name: string;
	status: "passed" | "failed" | "skipped";
	message?: string;
	details?: unknown;
	timestamp: string;
	duration: number;
}

export interface CloudGuardConfig {
	defaultCloud?: string;
	parallelExecution?: boolean;
	outputFormat?: "json" | "stdout" | "html";
	verbosity?: "normal" | "verbose" | "debug";
	ciMode?: boolean;
	credentials?: {
		aws?: Record<string, unknown>;
		azure?: Record<string, unknown>;
		gcp?: Record<string, unknown>;
	};
}

export interface Test {
	name: string;
	description: string;
	severity: "HIGH" | "MEDIUM" | "LOW";
	category: string;
	execute: () => Promise<TestResult>;
}
