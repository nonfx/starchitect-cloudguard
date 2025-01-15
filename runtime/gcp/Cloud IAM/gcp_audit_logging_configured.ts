import { ProjectsClient } from "@google-cloud/resource-manager";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Required audit log types that should be enabled
const REQUIRED_LOG_TYPES = ["ADMIN_READ", "DATA_READ", "DATA_WRITE"];

// Helper function to check if audit config has all required log types
function hasRequiredLogTypes(auditConfigs: any[]): boolean {
	if (!Array.isArray(auditConfigs)) return false;

	const configuredTypes = new Set<string>();

	for (const config of auditConfigs) {
		if (config.auditLogConfigs) {
			for (const logConfig of config.auditLogConfigs) {
				if (logConfig.logType) {
					configuredTypes.add(logConfig.logType);
				}
			}
		}
	}

	return REQUIRED_LOG_TYPES.every(type => configuredTypes.has(type));
}

// Main compliance check function
export async function checkAuditLoggingConfiguration(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const client = new ProjectsClient();
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get project IAM policy
		const [policy] = await client.getIamPolicy({
			resource: `projects/${projectId}`
		});

		if (!policy) {
			results.checks.push({
				resourceName: "Cloud Audit Logging",
				status: ComplianceStatus.ERROR,
				message: "Unable to retrieve IAM policy"
			});
			return results;
		}

		const auditConfigs = policy.auditConfigs || [];
		const isCompliant = hasRequiredLogTypes(auditConfigs);

		results.checks.push({
			resourceName: `Project ${projectId} Audit Logging`,
			status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
			message: isCompliant
				? undefined
				: `Missing required audit log types. Required: ${REQUIRED_LOG_TYPES.join(", ")}`
		});
	} catch (error) {
		results.checks.push({
			resourceName: "Cloud Audit Logging Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking audit logging configuration: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const results = await checkAuditLoggingConfiguration(projectId);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Cloud Audit Logging is configured properly",
	description:
		"It is recommended that Cloud Audit Logging is configured to track all admin activities and read write access to user data.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.1",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	serviceName: "Cloud Audit Logs",
	shortServiceName: "audit-logs",
	execute: checkAuditLoggingConfiguration
} satisfies RuntimeTest;
