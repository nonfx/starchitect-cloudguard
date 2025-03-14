import { InstancesClient } from "@google-cloud/compute";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check if IP forwarding is enabled
function isIpForwardingEnabled(instance: any): boolean {
	return instance.canIpForward === true;
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
		// List all compute instances in the specified zone
		const [instances] = await client.list({
			project: projectId,
			zone
		});

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
				status: isIpForwardingEnabled(instance) ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: isIpForwardingEnabled(instance)
					? `IP forwarding is enabled on instance ${instanceName}. This may allow unauthorized packet routing.`
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
	title: "Ensure That IP Forwarding Is Not Enabled on Instances",
	description:
		"Compute Engine instance cannot forward a packet unless the source IP address of the packet matches the IP address of the instance. IP forwarding should be disabled to prevent unauthorized packet routing and data loss.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_4.6",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	serviceName: "Google Compute Engine",
	shortServiceName: "compute",
	execute: checkIpForwardingDisabled
} satisfies RuntimeTest;
