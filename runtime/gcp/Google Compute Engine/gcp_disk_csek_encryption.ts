import { DisksClient } from "@google-cloud/compute";
import { listAllDisks } from "./list-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check if disk uses CSEK
function hasCSEKEncryption(disk: any): boolean {
	return disk.diskEncryptionKey && Object.keys(disk.diskEncryptionKey).length > 0;
}

// Main compliance check function
export async function checkDiskCSEKEncryption(
	projectId: string = process.env.GCP_PROJECT_ID || "",
	zone: string = process.env.GCP_ZONE || "us-central1-a"
): Promise<ComplianceReport> {
	const client = new DisksClient();
	const results: ComplianceReport = {
		checks: []
	};

	if (!projectId) {
		results.checks.push({
			resourceName: "Disk CSEK Encryption Check",
			status: ComplianceStatus.ERROR,
			message: "Project ID is not provided"
		});
		return results;
	}

	try {
		// List all disks in the specified zone using pagination
		const disks = await listAllDisks(projectId, zone);

		// No disks found
		if (!disks || disks.length === 0) {
			results.checks.push({
				resourceName: "GCP Compute Disks",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: `No compute disks found in zone ${zone}`
			});
			return results;
		}

		// Check each disk for CSEK encryption
		for (const disk of disks) {
			const diskName = disk.name || "Unknown Disk";
			const selfLink = disk.selfLink || undefined;

			results.checks.push({
				resourceName: diskName,
				resourceArn: selfLink,
				status: hasCSEKEncryption(disk) ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: !hasCSEKEncryption(disk)
					? `Disk ${diskName} in zone ${zone} is not encrypted with Customer-Supplied Encryption Keys (CSEK). Configure CSEK for enhanced security.`
					: undefined
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Disk CSEK Encryption Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking disk CSEK encryption: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const zone = process.env.GCP_ZONE;
	const results = await checkDiskCSEKEncryption(projectId, zone);
	printSummary(generateSummary(results));
}

// Export default with compliance check metadata
export default {
	title:
		"Ensure VM Disks for Critical VMs Are Encrypted With Customer-Supplied Encryption Key (CSEK)",
	description:
		"Customer-Supplied Encryption Keys (CSEK) are required for critical VM disks to ensure enhanced data protection and control over encryption keys.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_4.7",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	serviceName: "Google Compute Engine",
	shortServiceName: "compute",
	execute: checkDiskCSEKEncryption
} satisfies RuntimeTest;
