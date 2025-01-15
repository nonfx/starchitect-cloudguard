import { ApiKeysClient } from "@google-cloud/apikeys";
import { listAllKeys } from "./get-all-api-keys-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check API key application restrictions
function hasAppRestrictions(key: any): boolean {
	if (!key.restrictions) return false;

	// Check for HTTP referrers that are not wildcards
	const hasValidHttpReferrers =
		key.restrictions.browserKeyRestrictions?.allowedReferrers?.length > 0 &&
		!key.restrictions.browserKeyRestrictions.allowedReferrers.some(
			(referrer: string) => referrer === "*" || referrer === "*.[TLD]" || referrer === "*.[TLD]/*"
		);

	// Check for IP restrictions that are not 0.0.0.0/0 or ::0
	const hasValidIpRestrictions =
		key.restrictions.serverKeyRestrictions?.allowedIps?.length > 0 &&
		!key.restrictions.serverKeyRestrictions.allowedIps.some(
			(ip: string) => ip === "0.0.0.0" || ip === "0.0.0.0/0" || ip === "::0"
		);

	// Check for Android/iOS app restrictions
	const hasAndroidRestrictions =
		key.restrictions.androidKeyRestrictions?.allowedApplications?.length > 0;
	const hasIosRestrictions = key.restrictions.iosKeyRestrictions?.allowedBundleIds?.length > 0;

	return (
		hasValidHttpReferrers || hasValidIpRestrictions || hasAndroidRestrictions || hasIosRestrictions
	);
}

// Main compliance check function
export async function checkApiKeyAppRestrictions(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const client = new ApiKeysClient();
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// List all API keys for the project using pagination
		const keys = await listAllKeys(projectId);

		// No keys found
		if (!keys || keys.length === 0) {
			results.checks.push({
				resourceName: "GCP API Keys",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No API keys found in the project"
			});
			return results;
		}

		// Check each API key
		for (const key of keys) {
			const keyName = key.name || "Unknown API Key";

			results.checks.push({
				resourceName: keyName,
				resourceArn: key.name ?? undefined,
				status: hasAppRestrictions(key) ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: !hasAppRestrictions(key)
					? "API key must have application restrictions configured (HTTP referrers, IP addresses, or mobile apps)"
					: undefined
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "API Key Application Restrictions Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking API key application restrictions: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const results = await checkApiKeyAppRestrictions(projectId);
	printSummary(generateSummary(results));
}

// Export default with compliance check metadata
export default {
	title: "Ensure API Keys Are Restricted To Use by Only Specified Hosts and Apps",
	description:
		"API Keys should only be used for services in cases where other authentication methods are unavailable. In this case, unrestricted keys are insecure because they can be viewed publicly, such as from within a browser, or they can be accessed on a device where the key resides. It is recommended to restrict API key usage to trusted hosts, HTTP referrers and apps.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_1.13",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	serviceName: "Cloud Identity",
	shortServiceName: "cloud-identity",
	execute: checkApiKeyAppRestrictions
} satisfies RuntimeTest;
