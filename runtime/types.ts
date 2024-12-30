import type * as bunType from "bun:test";
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
	serviceName: string;
	shortServiceName: string;
};

export type RuntimeTest = RuntimeTestMeta & {
	execute: (...args: any[]) => Promise<ComplianceReport>;
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

declare global {
	const describe: typeof bunType.describe;
	const beforeEach: typeof bunType.beforeEach;
	const beforeAll: typeof bunType.beforeAll;
	const afterAll: typeof bunType.afterAll;
	const test: typeof bunType.test;
	const expect: typeof bunType.expect;
	const it: typeof bunType.it;
}
