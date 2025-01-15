import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { listAllZones } from "./get-all-zones-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check if DNSSEC is enabled
function isDnssecEnabled(zone: any): boolean {
	return zone.metadata?.dnssecConfig?.state === "on";
}

// Helper function to check if zone is public
function isPublicZone(zone: any): boolean {
	return zone.metadata?.visibility === "public";
}

// Main compliance check function
export async function checkDnssecEnabled(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const results: ComplianceReport = {
		checks: []
	};

	if (!projectId) {
		results.checks.push({
			resourceName: "DNSSEC Check",
			status: ComplianceStatus.ERROR,
			message: "Project ID is not provided"
		});
		return results;
	}

	try {
		// Get all zones using pagination
		const zones = await listAllZones(projectId);

		// No zones found
		if (!zones || zones.length === 0) {
			results.checks.push({
				resourceName: "GCP DNS Zones",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No DNS zones found in the project"
			});
			return results;
		}

		// Check each zone
		for (const zone of zones) {
			const metadata = zone.metadata || {};
			const zoneName = metadata.name || "Unknown Zone";
			const selfLink = metadata.id
				? `projects/${projectId}/managedZones/${metadata.id}`
				: undefined;

			// Only check public zones
			if (isPublicZone(zone)) {
				results.checks.push({
					resourceName: zoneName,
					resourceArn: selfLink,
					status: isDnssecEnabled(zone) ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: !isDnssecEnabled(zone)
						? `DNSSEC is not enabled for public DNS zone ${zoneName}. Enable it using 'gcloud dns managed-zones update ${zoneName} --dnssec-state on'`
						: undefined
				});
			} else {
				results.checks.push({
					resourceName: zoneName,
					resourceArn: selfLink,
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "Zone is not public"
				});
			}
		}
	} catch (error) {
		const errorMessage = error instanceof Error ? error.message : String(error);

		if (errorMessage.includes("permission denied") || errorMessage.includes("forbidden")) {
			results.checks.push({
				resourceName: "DNSSEC Check",
				status: ComplianceStatus.ERROR,
				message:
					"Insufficient permissions to check DNS zones. Required permission: dns.managedZones.list"
			});
		} else {
			results.checks.push({
				resourceName: "DNSSEC Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking DNSSEC status: ${errorMessage}`
			});
		}
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;

	if (!projectId) {
		console.error("Error: GCP_PROJECT_ID environment variable is not set");
		process.exit(1);
	}

	checkDnssecEnabled(projectId)
		.then(results => {
			printSummary(generateSummary(results));
		})
		.catch(error => {
			console.error("Error:", error.message);
			process.exit(1);
		});
}

// Export default with compliance check metadata
export default {
	title: "Ensure That DNSSEC Is Enabled for Cloud DNS",
	description:
		"Cloud Domain Name System (DNS) zones should have DNSSEC enabled to protect against DNS hijacking and man-in-the-middle attacks.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_3.3",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	serviceName: "Cloud DNS",
	shortServiceName: "dns",
	execute: checkDnssecEnabled
} satisfies RuntimeTest;
