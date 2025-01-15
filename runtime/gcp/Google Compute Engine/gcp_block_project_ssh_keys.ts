import { listAllInstances } from "./list-compute-resources-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check if project-wide SSH keys are blocked
function isProjectSSHKeysBlocked(instance: any): boolean {
	return (
		instance.metadata?.items?.some(
			(item: any) => item.key === "block-project-ssh-keys" && item.value === "true"
		) ?? false
	);
}

// Main compliance check function
export async function checkBlockProjectSSHKeys(
	projectId: string = process.env.GCP_PROJECT_ID || "",
	zone: string = process.env.GCP_ZONE || "us-central1-a"
): Promise<ComplianceReport> {
	const results: ComplianceReport = {
		checks: []
	};

	if (!projectId) {
		results.checks.push({
			resourceName: "Block Project SSH Keys Check",
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

		// Check each instance for blocked project SSH keys
		for (const instance of instances) {
			const instanceName = instance.name || "Unknown Instance";
			const selfLink = instance.selfLink || undefined;

			results.checks.push({
				resourceName: instanceName,
				resourceArn: selfLink,
				status: isProjectSSHKeysBlocked(instance) ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: !isProjectSSHKeysBlocked(instance)
					? `Instance ${instanceName} in zone ${zone} does not block project-wide SSH keys. Set block-project-ssh-keys metadata to true for enhanced security.`
					: undefined
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Block Project SSH Keys Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking blocked project SSH keys: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const zone = process.env.GCP_ZONE;
	const results = await checkBlockProjectSSHKeys(projectId, zone);
	printSummary(generateSummary(results));
}

// Export default with compliance check metadata
export default {
	title: "Ensure Block Project-Wide SSH Keys Is Enabled for VM Instances",
	description:
		"Block project-wide SSH keys to ensure that SSH access is controlled at the instance level, providing better security and access control.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_4.3",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	serviceName: "Google Compute Engine",
	shortServiceName: "compute",
	execute: checkBlockProjectSSHKeys
} satisfies RuntimeTest;
