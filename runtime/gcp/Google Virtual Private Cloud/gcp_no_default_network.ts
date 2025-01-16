import { listAllNetworks } from "../../utils/gcp/list-vpc-resources-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Main compliance check function
export async function checkDefaultNetwork(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const results: ComplianceReport = {
		checks: []
	};

	// Check if project ID is undefined or empty
	if (!projectId) {
		results.checks.push({
			resourceName: "Default Network Check",
			status: ComplianceStatus.ERROR,
			message: "Project ID is not provided"
		});
		return results;
	}

	try {
		// List all networks in the project using pagination
		const networks = await listAllNetworks(projectId);

		// No networks found
		if (!networks || networks.length === 0) {
			results.checks.push({
				resourceName: "GCP Networks",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No networks found in the project"
			});
			return results;
		}

		// Check for default network
		const defaultNetwork = networks.find(network => network.name === "default");

		if (defaultNetwork) {
			results.checks.push({
				resourceName: "default",
				resourceArn: defaultNetwork.selfLink ?? undefined,
				status: ComplianceStatus.FAIL,
				message:
					"Default network detected in project. Default networks should be deleted as they create preconfigured firewall rules that may not align with security requirements."
			});
		} else {
			results.checks.push({
				resourceName: "Project Networks",
				status: ComplianceStatus.PASS,
				message: "No default network found in the project"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Default Network Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking default network: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const results = await checkDefaultNetwork(projectId);
	printSummary(generateSummary(results));
}

// Export default with compliance check metadata
export default {
	title: "Ensure That the Default Network Does Not Exist in a Project",
	description:
		"To prevent use of default network a project should not have a default network. Default networks have preconfigured firewall rules and automatic subnet creation which may not align with security requirements.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_3.1",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	serviceName: "VPC Network",
	shortServiceName: "network",
	execute: checkDefaultNetwork
} satisfies RuntimeTest;
