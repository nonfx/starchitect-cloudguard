import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { listAllZones } from "../../utils/gcp/get-all-zones-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check if RSASHA1 is used for key signing
function isRSASHA1KeySigning(keySpecs: any[]): boolean {
	return (
		keySpecs?.some(
			(spec: any) =>
				spec.keyType === "keySigning" && spec.algorithm?.toLowerCase().includes("rsasha1")
		) ?? false
	);
}

// Main compliance check function
export async function checkDNSSECKeyAlgorithm(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const results: ComplianceReport = {
		checks: []
	};

	if (!projectId?.trim()) {
		results.checks.push({
			resourceName: "DNSSEC Key Algorithm Check",
			status: ComplianceStatus.ERROR,
			message: "Project ID is not provided"
		});
		return results;
	}

	try {
		// Get all zones using pagination
		const zones = await listAllZones(projectId);

		if (!zones || zones.length === 0) {
			results.checks.push({
				resourceName: "DNS Managed Zones",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No DNS managed zones found in the project"
			});
			return results;
		}

		// Check each zone's DNSSEC configuration
		for (const zone of zones) {
			const metadata = zone.metadata || {};
			const zoneName = metadata.name || "Unknown Zone";
			const zoneId = metadata.id;
			const dnssecConfig = metadata.dnssecConfig;

			if (!dnssecConfig || dnssecConfig.state !== "on") {
				results.checks.push({
					resourceName: zoneName,
					resourceArn: zoneId,
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "DNSSEC is not enabled for this zone"
				});
				continue;
			}

			const keySpecs = dnssecConfig.defaultKeySpecs;
			const usesRSASHA1 = isRSASHA1KeySigning(keySpecs);

			results.checks.push({
				resourceName: zoneName,
				resourceArn: zoneId,
				status: usesRSASHA1 ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: usesRSASHA1
					? "RSASHA1 is used for key signing. Use a stronger algorithm like RSASHA256, RSASHA512, ECDSAP256SHA256, or ECDSAP384SHA384"
					: undefined
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "DNSSEC Key Algorithm Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking DNSSEC key algorithms: ${error instanceof Error ? error.message : String(error)}`
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

	checkDNSSECKeyAlgorithm(projectId)
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
	title: "Ensure That RSASHA1 Is Not Used for the Key-Signing Key in Cloud DNS DNSSEC",
	description:
		"DNSSEC algorithm numbers in this registry may be used in CERT RRs. Zone signing (DNSSEC) and transaction security mechanisms (SIG(0) and TSIG) make use of particular subsets of these algorithms. The algorithm used for key signing should be a recommended one and it should be strong.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_3.4",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	serviceName: "Cloud DNS",
	shortServiceName: "dns",
	execute: checkDNSSECKeyAlgorithm
} satisfies RuntimeTest;
