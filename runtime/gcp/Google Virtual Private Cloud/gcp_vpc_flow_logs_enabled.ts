import { listAllSubnets } from "./list-vpc-resources-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Valid VPC Flow Log intervals
const VALID_INTERVALS = [
	"INTERVAL_5_SEC",
	"INTERVAL_30_SEC",
	"INTERVAL_1_MIN",
	"INTERVAL_5_MIN",
	"INTERVAL_10_MIN",
	"INTERVAL_15_MIN"
] as const;

type FlowLogInterval = (typeof VALID_INTERVALS)[number];

// Helper function to check if interval is valid
function isValidInterval(interval: string): interval is FlowLogInterval {
	return VALID_INTERVALS.includes(interval as FlowLogInterval);
}

// Helper function to check if subnet has valid flow log configuration
function hasValidFlowLogs(subnet: any): boolean {
	return (
		subnet.logConfig &&
		typeof subnet.logConfig === "object" &&
		isValidInterval(subnet.logConfig.aggregationInterval) &&
		subnet.logConfig.flowSampling === 1 &&
		subnet.logConfig.metadata === "INCLUDE_ALL_METADATA"
	);
}

// Helper function to check if subnet is eligible for flow logs
function isEligibleSubnet(subnet: any): boolean {
	return subnet.purpose !== "REGIONAL_MANAGED_PROXY" && subnet.purpose !== "GLOBAL_MANAGED_PROXY";
}

// Main compliance check function
export async function checkVPCFlowLogs(
	projectId: string = process.env.GCP_PROJECT_ID || "",
	region: string = process.env.GCP_REGION || "us-central1"
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

	try {
		// Get subnets for the specified region
		const subnets = await listAllSubnets(projectId, region);

		// No subnets found
		if (!subnets || subnets.length === 0) {
			results.checks.push({
				resourceName: "GCP VPC Subnets",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No VPC subnets found in any region of the project"
			});
			return results;
		}

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
					? "VPC Flow Logs must be enabled with a valid aggregation interval (5s to 15m), 100% sampling rate, and include all metadata"
					: undefined
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
	const region = process.env.GCP_REGION;
	const results = await checkVPCFlowLogs(projectId, region);
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
