import { v2 } from "@google-cloud/iam";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";

// Helper function to check if role is administrative
function isAdminRole(role: string): boolean {
	const adminRoles = ["roles/editor", "roles/owner"];
	return adminRoles.includes(role) || role.toLowerCase().includes("admin");
}

// Helper function to check if member is a service account
function isServiceAccount(member: string): boolean {
	return member.startsWith("serviceAccount:");
}

// Main compliance check function
export async function checkServiceAccountAdminPrivileges(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const results: ComplianceReport = {
		checks: []
	};

	// Check for missing project ID
	if (!projectId) {
		return {
			checks: [
				{
					resourceName: "Service Account Admin Check",
					status: ComplianceStatus.ERROR,
					message: "Missing required project ID"
				}
			]
		};
	}

	const client = new v2.PoliciesClient();

	try {
		// Get project IAM policy
		const response = await client.getPolicy({
			request: {
				resource: `projects/${projectId}/policies`
			}
		});
		const policy = response?.[0];

		if (!policy || !policy.bindings) {
			results.checks.push({
				resourceName: "GCP IAM Policy",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No IAM policy bindings found"
			});
			return results;
		}

		// Check each binding
		for (const binding of policy.bindings) {
			if (!binding.members || !binding.role) continue;

			const serviceAccounts = binding.members.filter(isServiceAccount);

			if (serviceAccounts.length > 0 && isAdminRole(binding.role)) {
				for (const sa of serviceAccounts) {
					results.checks.push({
						resourceName: sa,
						status: ComplianceStatus.FAIL,
						message: `Service account has administrative role: ${binding.role}`
					});
				}
			} else if (serviceAccounts.length > 0) {
				for (const sa of serviceAccounts) {
					results.checks.push({
						resourceName: sa,
						status: ComplianceStatus.PASS
					});
				}
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Service Account Admin Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking service account privileges: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const results = await checkServiceAccountAdminPrivileges(projectId);
	printSummary(generateSummary(results));
}

export default {
	title: "Service accounts should not have admin privileges",
	description:
		"Service accounts should not be granted administrative privileges to maintain security and prevent unauthorized access to Google Cloud resources.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_1.5",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "CRITICAL",
	execute: checkServiceAccountAdminPrivileges,
	serviceName: "Cloud IAM",
	shortServiceName: "iam"
} satisfies RuntimeTest;
