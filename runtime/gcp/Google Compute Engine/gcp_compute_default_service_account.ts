import { listAllInstances } from "./list-compute-resources-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check if instance uses default service account
function usesDefaultServiceAccount(instance: any): boolean {
	if (!instance.serviceAccounts || !Array.isArray(instance.serviceAccounts)) {
		return false;
	}

	return instance.serviceAccounts.some((sa: any) =>
		sa.email?.endsWith("-compute@developer.gserviceaccount.com")
	);
}

// Main compliance check function
export async function checkDefaultServiceAccount(
	projectId: string = process.env.GCP_PROJECT_ID || "",
	zone: string = process.env.GCP_ZONE || "us-central1-a"
): Promise<ComplianceReport> {
	const results: ComplianceReport = {
		checks: []
	};

	if (!projectId) {
		results.checks.push({
			resourceName: "Default Service Account Check",
			status: ComplianceStatus.ERROR,
			message: "Project ID is not provided"
		});
		return results;
	}

	try {
		// List all compute instances in the specified zone using pagination
		const instances = await listAllInstances(projectId, zone);

		// No instances found
		if (!instances || instances.length === 0) {
			results.checks.push({
				resourceName: "GCP Compute Instances",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: `No compute instances found in zone ${zone}`
			});
			return results;
		}

		// Check each instance for default service account usage
		for (const instance of instances) {
			const instanceName = instance.name || "Unknown Instance";
			const selfLink = instance.selfLink || undefined;

			results.checks.push({
				resourceName: instanceName,
				resourceArn: selfLink,
				status: usesDefaultServiceAccount(instance) ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: usesDefaultServiceAccount(instance)
					? `Instance ${instanceName} uses default compute service account. Configure a custom service account instead.`
					: undefined
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Default Service Account Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking default service account usage: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const zone = process.env.GCP_ZONE;
	const results = await checkDefaultServiceAccount(projectId, zone);
	printSummary(generateSummary(results));
}

// Export default with compliance check metadata
export default {
	title: "Ensure That Instances Are Not Configured To Use the Default Service Account",
	description:
		"Prevent default Compute Engine service account usage on instances to minimize security risks and privilege escalation.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_4.1",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	serviceName: "Google Compute Engine",
	shortServiceName: "compute",
	execute: checkDefaultServiceAccount
} satisfies RuntimeTest;
