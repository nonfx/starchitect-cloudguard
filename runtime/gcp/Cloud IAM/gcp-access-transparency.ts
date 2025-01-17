import { ProjectsClient } from "@google-cloud/resource-manager";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check if Access Transparency is enabled
async function isAccessTransparencyEnabled(projectId: string): Promise<boolean> {
	const client = new ProjectsClient();

	try {
		const [project] = await client.getProject({
			name: `projects/${projectId}`
		});

		// Check project settings for Access Transparency
		// @ts-ignore - settings property exists but is not in type definition
		return project?.settings?.accessTransparencyEnabled === true;
	} catch (error) {
		throw new Error(
			`Failed to check Access Transparency status: ${error instanceof Error ? error.message : String(error)}`
		);
	}
}

// Main compliance check function
export async function checkAccessTransparencyEnabled(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const results: ComplianceReport = {
		checks: []
	};

	if (!projectId) {
		results.checks.push({
			resourceName: "Access Transparency Check",
			status: ComplianceStatus.ERROR,
			message: "Project ID is not provided"
		});
		return results;
	}

	try {
		const isEnabled = await isAccessTransparencyEnabled(projectId);

		results.checks.push({
			resourceName: `Project ${projectId}`,
			status: isEnabled ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
			message: isEnabled ? undefined : "Access Transparency is not enabled for the project"
		});
	} catch (error) {
		results.checks.push({
			resourceName: "Access Transparency Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking Access Transparency: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const results = await checkAccessTransparencyEnabled(projectId);
	printSummary(generateSummary(results));
}

// Export default with compliance check metadata
export default {
	title: "Ensure 'Access Transparency' is 'Enabled'",
	description:
		"GCP Access Transparency provides audit logs for all actions that Google personnel take in your Google Cloud resources. Controlling access to your information is one of the foundations of information security. Given that Google Employees do have access to your organizations' projects for support reasons, you should have logging in place to view who, when, and why your information is being accessed.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.12",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	serviceName: "Cloud IAM",
	shortServiceName: "iam",
	execute: checkAccessTransparencyEnabled
} satisfies RuntimeTest;
