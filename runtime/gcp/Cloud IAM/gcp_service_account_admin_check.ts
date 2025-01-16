import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { getIAMPolicy } from "../../utils/gcp/get-iam-policies-utils.js";

// Helper function to check if role is administrative
function isAdminRole(role: string): boolean {
	const adminRoles = ["roles/editor", "roles/owner"];
	const roleLower = role.toLowerCase();
	return adminRoles.includes(role) || roleLower.includes("admin");
}

// Helper function to check if member is a user-managed service account
function isUserManagedServiceAccount(member: string, projectId: string): boolean {
	// Check for pattern: SERVICE_ACCOUNT_NAME@PROJECT_ID.iam.gserviceaccount.com
	return (
		member.startsWith("serviceAccount:") &&
		member.endsWith(".iam.gserviceaccount.com") &&
		member.includes(projectId) &&
		!member.includes("@developer.gserviceaccount.com") && // Exclude Google-managed compute service account
		!member.includes("@appspot.gserviceaccount.com") && // Exclude Google-managed App Engine service account
		!member.includes("@cloudservices.gserviceaccount.com") && // Exclude Google-managed Cloud Services service account
		!member.includes("@system.gserviceaccount.com") // Exclude Google-managed system service accounts
	);
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

	try {
		// Get project IAM policy
		const policy = await getIAMPolicy(projectId);

		if (!policy || !policy.bindings) {
			results.checks.push({
				resourceName: "GCP IAM Policy",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No IAM policy bindings found"
			});
			return results;
		}

		let foundServiceAccounts = false;

		// Check each binding
		for (const binding of policy.bindings) {
			if (!binding.members || !binding.role) continue;

			const serviceAccounts = binding.members.filter((member: string) =>
				isUserManagedServiceAccount(member, projectId)
			);

			if (serviceAccounts.length > 0) {
				foundServiceAccounts = true;
				if (isAdminRole(binding.role)) {
					for (const sa of serviceAccounts) {
						results.checks.push({
							resourceName: sa.replace("serviceAccount:", ""),
							status: ComplianceStatus.FAIL,
							message: `Service account has administrative role: ${binding.role}`
						});
					}
				} else {
					for (const sa of serviceAccounts) {
						results.checks.push({
							resourceName: sa.replace("serviceAccount:", ""),
							status: ComplianceStatus.PASS
						});
					}
				}
			}
		}

		// If no service accounts found, return NOTAPPLICABLE
		if (!foundServiceAccounts) {
			results.checks.push({
				resourceName: "GCP Service Accounts",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No user-managed service accounts found in the project"
			});
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
