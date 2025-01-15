import { InstancesClient } from "@google-cloud/compute";
import { listAllInstances } from "./list-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check if IP forwarding is disabled
function isIpForwardingDisabled(instance: any): boolean {
	return instance.canIpForward !== true;
}

// Main compliance check function
export async function checkIpForwardingDisabled(
	projectId: string = process.env.GCP_PROJECT_ID || "",
	zone: string = process.env.GCP_ZONE || "us-central1-a"
): Promise<ComplianceReport> {
	const client = new InstancesClient();
	const results: ComplianceReport = {
		checks: []
	};

	if (!projectId) {
		results.checks.push({
			resourceName: "IP Forwarding Check",
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

		// Check each instance for IP forwarding
		for (const instance of instances) {
			const instanceName = instance.name || "Unknown Instance";
			const selfLink = instance.selfLink || undefined;

			results.checks.push({
				resourceName: instanceName,
				resourceArn: selfLink,
				status: isIpForwardingDisabled(instance) ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: !isIpForwardingDisabled(instance)
					? `Instance ${instanceName} has IP forwarding enabled. Disable IP forwarding unless required for network routing.`
					: undefined
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "IP Forwarding Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking IP forwarding: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const zone = process.env.GCP_ZONE;
	const results = await checkIpForwardingDisabled(projectId, zone);
	printSummary(generateSummary(results));
}

// Export default with compliance check metadata
export default {
	title: "Ensure That IP Forwarding is Disabled on Instances",
	description:
		"IP forwarding should be disabled on instances unless required for network routing to prevent potential security risks.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_4.4",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	serviceName: "Google Compute Engine",
	shortServiceName: "compute",
	execute: checkIpForwardingDisabled
} satisfies RuntimeTest;
