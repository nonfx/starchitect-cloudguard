import { InstancesClient } from "@google-cloud/compute";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check if an instance has a public IP
function hasPublicIP(instance: any): boolean {
	return (
		instance.networkInterfaces &&
		Array.isArray(instance.networkInterfaces) &&
		instance.networkInterfaces.some(
			(networkInterface: any) =>
				networkInterface.accessConfigs && networkInterface.accessConfigs.length > 0
		)
	);
}

// Main compliance check function
export async function checkComputeInstancePublicIPs(
	projectId: string = process.env.GCP_PROJECT_ID || "",
	zone: string = process.env.GCP_ZONE || "us-central1-a" // Default to us-central1-a if not specified
): Promise<ComplianceReport> {
	const client = new InstancesClient();
	const results: ComplianceReport = {
		checks: []
	};

	if (!projectId) {
		results.checks.push({
			resourceName: "Compute Instance Public IP Check",
			status: ComplianceStatus.ERROR,
			message: "Project ID is not provided"
		});
		return results;
	}

	try {
		// List all compute instances in the specified zone
		const [instances] = await client.list({
			project: projectId,
			zone: zone
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

		// Check each instance for public IP
		for (const instance of instances) {
			const instanceName = instance.name || "Unknown Instance";
			const selfLink = instance.selfLink || undefined;

			results.checks.push({
				resourceName: instanceName,
				resourceArn: selfLink,
				status: hasPublicIP(instance) ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: hasPublicIP(instance)
					? `Instance ${instanceName} in zone ${zone} has a public IP address configured. Remove access_config from network interfaces to prevent public access.`
					: undefined
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Compute Instance Public IP Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking compute instance public IPs: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const zone = process.env.GCP_ZONE; // Optional: will use default if not provided
	const results = await checkComputeInstancePublicIPs(projectId);
	printSummary(generateSummary(results));
}

// Export default with compliance check metadata
export default {
	title: "Ensure That Compute Instances Do Not Have Public IP Addresses",
	description:
		"Compute instances should not be configured to have external IP addresses to reduce attack surface.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_4.9",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	serviceName: "Google Compute Engine",
	shortServiceName: "compute",
	execute: checkComputeInstancePublicIPs
} satisfies RuntimeTest;
