import { listAllKeys } from "./list-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check API key restrictions
function hasApiRestrictions(key: any): boolean {
	// Check if key has restrictions and at least one API target
	return (
		key.restrictions &&
		Array.isArray(key.restrictions) &&
		key.restrictions.length > 0 &&
		key.restrictions.some(
			(restriction: any) =>
				restriction.apiTargets &&
				Array.isArray(restriction.apiTargets) &&
				restriction.apiTargets.length > 0
		)
	);
}

// Main compliance check function
export async function checkApiKeyRestrictions(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
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
				resourceArn: key.name ?? undefined, // Use nullish coalescing to handle potential null/undefined
				status: hasApiRestrictions(key) ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: !hasApiRestrictions(key)
					? "API key must have API target restrictions configured to limit access to only required APIs"
					: undefined
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "API Key Restrictions Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking API key restrictions: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const results = await checkApiKeyRestrictions(projectId);
	printSummary(generateSummary(results));
}

// Export default with compliance check metadata
export default {
	title: "Ensure API Keys Are Restricted to Only APIs That Application Needs Access",
	description:
		"API Keys should only be used for services in cases where other authentication methods are unavailable. API keys are always at risk because they can be viewed publicly, such as from within a browser, or they can be accessed on a device where the key resides.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_1.14",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	serviceName: "Cloud Identity",
	shortServiceName: "cloud-identity",
	execute: checkApiKeyRestrictions
} satisfies RuntimeTest;
