import { ApiKeysClient } from "@google-cloud/apikeys";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check if API key is older than 90 days
function isKeyOlderThan90Days(key: any): boolean {
	if (!key.createTime) return false;

	const createDate = new Date(key.createTime);
	const now = new Date();
	const diffInDays = Math.floor((now.getTime() - createDate.getTime()) / (1000 * 60 * 60 * 24));

	return diffInDays > 90;
}

// Main compliance check function
export async function checkApiKeyRotation(projectId?: string): Promise<ComplianceReport> {
	const client = new ApiKeysClient();
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get effective project ID
		const effectiveProjectId = projectId || process.env.GCP_PROJECT_ID;
		if (!effectiveProjectId || effectiveProjectId.trim() === "") {
			return {
				checks: [
					{
						resourceName: "GCP API Keys",
						status: ComplianceStatus.NOTAPPLICABLE,
						message: "No API keys found in the project"
					}
				]
			};
		}

		// Clean the project ID - remove any 'projects/' prefix and trim
		const cleanProjectId = effectiveProjectId.replace(/^projects\//, "").trim();

		// List API keys for the project
		// Parent format should be: projects/{project}/locations/{location}
		const [keys] = await client.listKeys({
			parent: `projects/${cleanProjectId}/locations/global`
		});

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
			const createTime = key.createTime || "Unknown";

			results.checks.push({
				resourceName: keyName,
				resourceArn: key.name ?? undefined,
				status: isKeyOlderThan90Days(key) ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: isKeyOlderThan90Days(key)
					? `API key was created on ${createTime} and has not been rotated in the last 90 days`
					: undefined
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "API Key Rotation Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking API key rotation: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const results = await checkApiKeyRotation(projectId);
	printSummary(generateSummary(results));
}

// Export default with compliance check metadata
export default {
	title: "Ensure API Keys Are Rotated Every 90 Days",
	description:
		"API Keys should only be used for services in cases where other authentication methods are unavailable. If they are in use it is recommended to rotate API keys every 90 days.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_1.15",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	serviceName: "Cloud IAM",
	shortServiceName: "iam",
	execute: checkApiKeyRotation
} satisfies RuntimeTest;
