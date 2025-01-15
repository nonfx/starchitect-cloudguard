import { InstancesClient } from "@google-cloud/compute";
import { listAllInstances } from "./list-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check if Shielded VM is properly configured
function isShieldedVMEnabled(instance: any): boolean {
	return (
		instance.shieldedInstanceConfig &&
		instance.shieldedInstanceConfig.enableVtpm === true &&
		instance.shieldedInstanceConfig.enableIntegrityMonitoring === true
	);
}

// Main compliance check function
export async function checkShieldedVMEnabled(
	projectId: string = process.env.GCP_PROJECT_ID || "",
	zone: string = process.env.GCP_ZONE || "us-central1-a"
): Promise<ComplianceReport> {
	const client = new InstancesClient();
	const results: ComplianceReport = {
		checks: []
	};

	if (!projectId) {
		results.checks.push({
			resourceName: "Shielded VM Check",
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

		// Check each instance for Shielded VM configuration
		for (const instance of instances) {
			const instanceName = instance.name || "Unknown Instance";
			const selfLink = instance.selfLink || undefined;

			results.checks.push({
				resourceName: instanceName,
				resourceArn: selfLink,
				status: isShieldedVMEnabled(instance) ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: !isShieldedVMEnabled(instance)
					? `Instance ${instanceName} does not have Shielded VM properly configured. Both vTPM and Integrity Monitoring must be enabled.`
					: undefined
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Shielded VM Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking Shielded VM configuration: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const zone = process.env.GCP_ZONE;
	const results = await checkShieldedVMEnabled(projectId, zone);
	printSummary(generateSummary(results));
}

// Export default with compliance check metadata
export default {
	title: "Ensure Compute Instances Are Launched With Shielded VM Enabled",
	description:
		"To defend against advanced threats and ensure that the boot loader and firmware on your VMs are signed and untampered, Compute instances must have Shielded VM enabled.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_4.8",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	serviceName: "Google Compute Engine",
	shortServiceName: "compute",
	execute: checkShieldedVMEnabled
} satisfies RuntimeTest;
