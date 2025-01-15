import { ServiceUsageClient } from "@google-cloud/service-usage";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Main compliance check function
export async function checkCloudAssetInventoryEnabled(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const client = new ServiceUsageClient();
	const results: ComplianceReport = {
		checks: []
	};

	if (!projectId) {
		results.checks.push({
			resourceName: "Cloud Asset Inventory Check",
			status: ComplianceStatus.ERROR,
			message: "Project ID is not provided"
		});
		return results;
	}

	try {
		// Check if Cloud Asset API is enabled using getService
		const serviceName = "cloudasset.googleapis.com";
		const request = {
			name: `projects/${projectId}/services/${serviceName}`
		};

		const [service] = await client.getService(request);

		results.checks.push({
			resourceName: "Cloud Asset Inventory API",
			resourceArn: `projects/${projectId}/services/${serviceName}`,
			status: service.state === "ENABLED" ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
			message:
				service.state !== "ENABLED"
					? "Cloud Asset Inventory API is not enabled. Enable it using 'gcloud services enable cloudasset.googleapis.com' to track assets and maintain compliance."
					: undefined
		});
	} catch (error) {
		const errorMessage = error instanceof Error ? error.message : String(error);

		// Handle specific error cases
		if (errorMessage.includes("Permission denied") || errorMessage.includes("forbidden")) {
			results.checks.push({
				resourceName: "Cloud Asset Inventory Check",
				status: ComplianceStatus.ERROR,
				message:
					"Insufficient permissions to check Cloud Asset Inventory API status. Ensure you have the required permissions: serviceusage.services.get"
			});
		} else if (errorMessage.includes("not found")) {
			results.checks.push({
				resourceName: "Cloud Asset Inventory API",
				status: ComplianceStatus.FAIL,
				message:
					"Cloud Asset Inventory API is not enabled. Enable it using 'gcloud services enable cloudasset.googleapis.com'"
			});
		} else {
			results.checks.push({
				resourceName: "Cloud Asset Inventory Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Cloud Asset Inventory status: ${errorMessage}`
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

	checkCloudAssetInventoryEnabled(projectId)
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
	title: "Ensure Cloud Asset Inventory Is Enabled",
	description:
		"GCP Cloud Asset Inventory provides historical view of GCP resources and IAM policies through a time-series database. The service should be enabled for security tracking and compliance auditing.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.13",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	serviceName: "Cloud Asset Inventory",
	shortServiceName: "cloudasset",
	execute: checkCloudAssetInventoryEnabled
} satisfies RuntimeTest;
