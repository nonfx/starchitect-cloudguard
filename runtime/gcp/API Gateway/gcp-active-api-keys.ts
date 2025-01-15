import { listAllKeys } from "./get-api-gateway-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check if API key is active
function isKeyActive(key: any): boolean {
	return (
		key.displayName && !key.deleted && key.keyString // Check if key has an actual value
	);
}

// Main compliance check function
export async function checkActiveApiKeys(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	// Check for missing project ID first
	if (!projectId) {
		return {
			checks: [
				{
					resourceName: "API Key Activity Check",
					status: ComplianceStatus.ERROR,
					message: "Missing required project ID"
				}
			]
		};
	}

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
				status: ComplianceStatus.PASS,
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
				status: isKeyActive(key) ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: !isKeyActive(key)
					? "Inactive or deleted API key detected. Remove unused API keys to reduce security risks."
					: undefined
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "API Key Activity Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking API key activity: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const results = await checkActiveApiKeys(projectId);
	printSummary(generateSummary(results));
}

// Export default with compliance check metadata
export default {
	title: "Ensure API Keys Only Exist for Active Services",
	description:
		"API Keys should only be used for services in cases where other authentication methods are unavailable. Unused keys with their permissions in tact may still exist within a project. Keys are insecure because they can be viewed publicly, such as from within a browser, or they can be accessed on a device where the key resides. It is recommended to use standard authentication flow instead.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_1.12",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	serviceName: "API Keys",
	shortServiceName: "apikeys",
	execute: checkActiveApiKeys
} satisfies RuntimeTest;
