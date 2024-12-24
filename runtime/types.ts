export enum ComplianceStatus {
	PASS = "PASS",
	FAIL = "FAIL",
	ERROR = "ERROR",
	NOTAPPLICABLE = "NOTAPPLICABLE"
}

export type RuntimeTestMeta = {
	title: string;
	description: string;
	controls: ComplianceControl[];
	severity: "HIGH" | "MEDIUM" | "LOW";
	category?: string;
};

export type RuntimeTest = RuntimeTestMeta & {
	execute: () => Promise<ComplianceReport>;
};

export interface ResourceComplianceCheck {
	resourceName: string;
	resourceArn?: string;
	status: ComplianceStatus;
	message?: string;
}

export interface ComplianceReport {
	checks: ResourceComplianceCheck[];
}

export interface ComplianceControl {
	id: string;
	document: string;
}

export interface ComplianceReportWithStats {
	checks: ResourceComplianceCheck[];
	summary: ComplianceStatistics;
}

export interface ComplianceStatistics {
	pass: number;
	fail: number;
	error: number;
	na: number;
}
