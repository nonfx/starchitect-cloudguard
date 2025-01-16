import { listAllInstances, getProject } from "../../utils/gcp/list-compute-resources-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check if OS login is enabled in metadata
function isOsLoginEnabled(metadata: any): boolean {
	if (!metadata) return false;
	return metadata.some((item: any) => item.key === "enable-oslogin" && item.value === "true");
}

// Main compliance check function
export async function checkOsLoginEnabled(
	projectId: string = process.env.GCP_PROJECT_ID || "",
	zone: string = process.env.GCP_ZONE || "us-central1-a" // Default zone
): Promise<ComplianceReport> {
	const results: ComplianceReport = {
		checks: []
	};

	if (!projectId) {
		results.checks.push({
			resourceName: "OS Login Check",
			status: ComplianceStatus.ERROR,
			message: "Project ID is not provided"
		});
		return results;
	}

	try {
		// Get project metadata
		const project = await getProject(projectId);

		// Check project-level OS login setting
		if (project?.commonInstanceMetadata?.items) {
			const osLoginEnabled = isOsLoginEnabled(project.commonInstanceMetadata.items);
			results.checks.push({
				resourceName: `Project ${projectId} Metadata`,
				resourceArn: project.selfLink || undefined,
				status: osLoginEnabled ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: osLoginEnabled
					? undefined
					: "OS login should be enabled at project level for centralized SSH key management"
			});

			// If OS login is enabled at project level, we don't need to check instances
			if (osLoginEnabled) {
				return results;
			}
		}

		// Get all instances in the specified zone using pagination
		const instances = await listAllInstances(projectId, zone);

		if (!instances || instances.length === 0) {
			results.checks.push({
				resourceName: "GCP Compute Instances",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: `No compute instances found in zone ${zone}`
			});
			return results;
		}

		// Check each instance
		for (const instance of instances) {
			const instanceName = instance.name || "Unknown Instance";
			const osLoginEnabled = instance.metadata?.items
				? isOsLoginEnabled(instance.metadata.items)
				: false;

			results.checks.push({
				resourceName: instanceName,
				resourceArn: instance.selfLink || undefined,
				status: osLoginEnabled ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: osLoginEnabled
					? undefined
					: `Instance ${instanceName} in zone ${zone} should have OS login enabled either at project level or instance level`
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "OS Login Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking OS login status: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const zone = process.env.GCP_ZONE; // Optional: will use default if not provided
	const results = await checkOsLoginEnabled(projectId, zone);
	printSummary(generateSummary(results));
}

// Export default with compliance check metadata
export default {
	title: "Ensure Oslogin Is Enabled for a Project",
	description:
		"Enable OS login in GCP projects to bind SSH certificates with IAM users for centralized SSH key management. This helps in automated SSH key pair management and efficient handling of user access revocation.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_4.4",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	serviceName: "Google Compute Engine",
	shortServiceName: "compute",
	execute: checkOsLoginEnabled
} satisfies RuntimeTest;
