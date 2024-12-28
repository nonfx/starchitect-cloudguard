import type { ComplianceReport, ComplianceStatus, RuntimeTest } from "../../runtime/types.js";

export * from "../../runtime/types.js";

export interface TestResult {
	// name: string;
	status: ComplianceStatus;
	message?: string;
	// details?: unknown;
	timestamp: number;
	duration: number;
	test: Omit<RuntimeTest, "execute">;
	checks: ComplianceReport;
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
