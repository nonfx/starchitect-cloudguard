import { SubnetworksClient, RegionsClient } from "@google-cloud/compute";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check if subnet has valid flow log configuration
function hasValidFlowLogs(subnet: any): boolean {
	return (
		subnet.logConfig &&
		Array.isArray(subnet.logConfig) &&
		subnet.logConfig.length > 0 &&
		subnet.logConfig.every((config: any) => {
			return config.aggregationInterval && config.flowSampling === 1 && config.metadata;
		})
	);
}

// Helper function to check if subnet is eligible for flow logs
function isEligibleSubnet(subnet: any): boolean {
	return subnet.purpose !== "REGIONAL_MANAGED_PROXY" && subnet.purpose !== "GLOBAL_MANAGED_PROXY";
}

// Function to get all available regions
async function getRegions(projectId: string): Promise<string[]> {
	const regionsClient = new RegionsClient();
	try {
		const [regions] = await regionsClient.list({
			project: projectId,
			maxResults: 500
		});

		return regions
			.filter(region => region.name && region.status === "UP")
			.map(region => region.name);
	} catch (error) {
		console.error("Error fetching regions:", error);
		return [];
	}
}

// Main compliance check function
export async function checkVPCFlowLogs(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const results: ComplianceReport = {
		checks: []
	};

	if (!projectId) {
		results.checks.push({
			resourceName: "VPC Flow Logs Check",
			status: ComplianceStatus.ERROR,
			message: "Project ID is not provided"
		});
		return results;
	}

	const subnetworksClient = new SubnetworksClient();
	const regions = await getRegions(projectId);

	if (regions.length === 0) {
		results.checks.push({
			resourceName: "VPC Flow Logs Check",
			status: ComplianceStatus.ERROR,
			message: "Unable to fetch regions for the project"
		});
		return results;
	}

	try {
		let totalSubnets = 0;

		// Check subnets in each region
		for (const region of regions) {
			try {
				const [subnets] = await subnetworksClient.list({
					project: projectId,
					region: region,
					maxResults: 500
				});

				if (subnets && subnets.length > 0) {
					totalSubnets += subnets.length;

					// Process each subnet in the region
					for (const subnet of subnets) {
						const subnetName = subnet.name || "Unknown Subnet";
						const selfLink = subnet.selfLink || undefined;

						if (!isEligibleSubnet(subnet)) {
							results.checks.push({
								resourceName: subnetName,
								resourceArn: selfLink,
								status: ComplianceStatus.NOTAPPLICABLE,
								message: "Subnet is not eligible for flow logs configuration"
							});
							continue;
						}

						results.checks.push({
							resourceName: subnetName,
							resourceArn: selfLink,
							status: hasValidFlowLogs(subnet) ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
							message: !hasValidFlowLogs(subnet)
								? "VPC Flow Logs must be enabled with 5-second aggregation interval, 100% sampling rate, and include all metadata"
								: undefined
						});
					}
				}
			} catch (error) {
				console.error(`Error checking subnets in region ${region}:`, error);
				// Continue with other regions if one fails
				continue;
			}
		}

		if (totalSubnets === 0) {
			results.checks.push({
				resourceName: "GCP VPC Subnets",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No VPC subnets found in any region of the project"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "VPC Flow Logs Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking VPC flow logs: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const results = await checkVPCFlowLogs(projectId);
	printSummary(generateSummary(results));
}

// Export default with compliance check metadata
export default {
	title: "Ensure that VPC Flow Logs is Enabled for Every Subnet in a VPC Network",
	description:
		"VPC Flow Logs must be enabled on all business-critical VPC subnets to capture and monitor IP traffic for security and analysis purposes.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_3.8",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	serviceName: "VPC Network",
	shortServiceName: "vpc",
	execute: checkVPCFlowLogs
} satisfies RuntimeTest;