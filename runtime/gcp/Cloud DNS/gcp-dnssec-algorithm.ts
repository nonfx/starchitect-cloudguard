import { listAllZones } from "../../utils/gcp/get-all-zones-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check if DNSSEC uses RSASHA1
function usesRSASHA1(dnssecConfig: any): boolean {
	if (!dnssecConfig?.defaultKeySpecs) return false;

	return dnssecConfig.defaultKeySpecs.some(
		(keySpec: any) =>
			keySpec.keyType === "zoneSigning" && keySpec.algorithm?.toLowerCase() === "rsasha1"
	);
}

// Main compliance check function
export async function checkDNSSECAlgorithm(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const results: ComplianceReport = {
		checks: []
	};

	if (!projectId?.trim()) {
		results.checks.push({
			resourceName: "DNSSEC Algorithm Check",
			status: ComplianceStatus.ERROR,
			message: "Project ID is not provided"
		});
		return results;
	}

	try {
		// List all zones using pagination
		const zones = await listAllZones(projectId);

		// No zones found
		if (!zones || zones.length === 0) {
			results.checks.push({
				resourceName: "GCP DNS Managed Zones",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No DNS managed zones found in the project"
			});
			return results;
		}

		// Check each zone's DNSSEC configuration
		for (const zone of zones) {
			const metadata = zone.metadata || {};
			const zoneName = metadata.name || "Unknown Zone";
			const dnssecConfig = metadata.dnssecConfig;

			// Skip if DNSSEC is not enabled
			if (!dnssecConfig || dnssecConfig.state !== "on") {
				results.checks.push({
					resourceName: zoneName,
					resourceArn: metadata.id,
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "DNSSEC is not enabled for this zone"
				});
				continue;
			}

			results.checks.push({
				resourceName: zoneName,
				resourceArn: metadata.id,
				status: usesRSASHA1(dnssecConfig) ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: usesRSASHA1(dnssecConfig)
					? "Zone is using RSASHA1 for zone-signing key which is not recommended"
					: undefined
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "DNSSEC Algorithm Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking DNSSEC algorithm: ${error instanceof Error ? error.message : String(error)}`
		});
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

	checkDNSSECAlgorithm(projectId)
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
	title: "Ensure That RSASHA1 Is Not Used for the Zone-Signing Key in Cloud DNS DNSSEC",
	description:
		"This rule ensures that RSASHA1 is not used for DNS zone-signing keys in Google Cloud DNS DNSSEC for enhanced security.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_3.5",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	serviceName: "Cloud DNS",
	shortServiceName: "dns",
	execute: checkDNSSECAlgorithm
} satisfies RuntimeTest;
