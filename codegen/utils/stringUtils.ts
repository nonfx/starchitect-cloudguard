export enum ComplianceStatus {
	PASS = "PASS",
	FAIL = "FAIL",
	ERROR = "ERROR",
	NOTAPPLICABLE = "NOTAPPLICABLE"
}

export function normalizeArn(arn: string): string {
	const normalized = arn.trim();
	if (!normalized.startsWith("arn:aws:")) {
		throw new Error("Invalid ARN format");
	}
	return normalized;
}

export function getServiceFromArn(arn: string): string {
	const normalized = normalizeArn(arn);
	const parts = normalized.split(":");
	if (parts.length < 3) {
		throw new Error("Invalid ARN format");
	}
	const service = parts[2];
	if (!service) {
		throw new Error("Invalid ARN: missing service");
	}
	return service;
}

export function getResourceFromArn(arn: string): string {
	const normalized = normalizeArn(arn);
	const parts = normalized.split(":");
	if (parts.length < 6) {
		throw new Error("Invalid ARN format");
	}
	const resource = parts[5];
	if (!resource) {
		throw new Error("Invalid ARN: missing resource");
	}
	return resource;
}

export function generateSummary(results: ComplianceReport): ComplianceReportWithStats {
	const pass = results.checks.filter(r => r.status === ComplianceStatus.PASS).length;
	const fail = results.checks.filter(r => r.status === ComplianceStatus.FAIL).length;
	const error = results.checks.filter(r => r.status === ComplianceStatus.ERROR).length;
	const na = results.checks.filter(r => r.status === ComplianceStatus.NOTAPPLICABLE).length;

	return {
		...results,
		summary: {
			pass,
			fail,
			error,
			na
		}
	};
}

export function printSummary(summary: ComplianceReportWithStats) {
	const { pass, fail, error, na } = summary.summary;

	console.log("Passing Resources:");
	summary.checks
		.filter(r => r.status === ComplianceStatus.PASS)
		.forEach(r => console.log(`  - ${r.resourceName}`));

	console.log("Failing Resources:");
	summary.checks
		.filter(r => r.status === ComplianceStatus.FAIL)
		.forEach(r => console.log(`  - ${r.resourceName} - ${r.message}`));

	console.log("Errored Resources:");
	summary.checks
		.filter(r => r.status === ComplianceStatus.ERROR)
		.forEach(r => console.log(`  - ${r.resourceName} - ${r.message}`));

	console.log("Not Applicable Resources:");
	summary.checks
		.filter(r => r.status === ComplianceStatus.NOTAPPLICABLE)
		.forEach(r => console.log(`  - ${r.resourceName}`));

	console.log(`Summary: ${pass} passing, ${fail} failing, ${error} errored, ${na} not applicable`);
}

export interface ResourceComplianceCheck {
	resourceName: string;
	resourceArn?: string;
	status: ComplianceStatus;
	message?: string;
}
export interface ComplianceReport {
	checks: ResourceComplianceCheck[];
	metadoc: ComplianceMetadata;
}

export interface ComplianceMetadata {
	title: string;
	description: string;
	controls: ComplianceControl[];
}

export interface ComplianceControl {
	id: string;
	document: string;
}

export interface ComplianceReportWithStats {
	checks: ResourceComplianceCheck[];
	metadoc: ComplianceMetadata;
	summary: ComplianceStatistics;
}

export interface ComplianceStatistics {
	pass: number;
	fail: number;
	error: number;
	na: number;
}
