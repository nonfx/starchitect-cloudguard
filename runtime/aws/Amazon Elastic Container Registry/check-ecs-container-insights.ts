import { DescribeClustersCommand, ECSClient, ListClustersCommand } from "@aws-sdk/client-ecs";
import { generateSummary, printSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkEcsContainerInsights(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new ECSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all cluster ARNs
		const listCommand = new ListClustersCommand({});
		const listResponse = await client.send(listCommand);

		if (!listResponse.clusterArns || listResponse.clusterArns.length === 0) {
			results.checks = [
				{
					resourceName: "No ECS Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No ECS clusters found in the region"
				}
			];
			return results;
		}

		// Get detailed information for each cluster
		const describeCommand = new DescribeClustersCommand({
			clusters: listResponse.clusterArns
		});
		const describeResponse = await client.send(describeCommand);

		if (!describeResponse.clusters) {
			throw new Error("Failed to get cluster details");
		}

		// Check each cluster for Container Insights
		for (const cluster of describeResponse.clusters) {
			if (!cluster.clusterName || !cluster.clusterArn) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without name or ARN"
				});
				continue;
			}

			// Check if Container Insights is enabled
			const insightsEnabled = cluster.settings?.some(
				setting => setting.name === "containerInsights" && setting.value === "enabled"
			);

			results.checks.push({
				resourceName: cluster.clusterName,
				resourceArn: cluster.clusterArn,
				status: insightsEnabled ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: insightsEnabled ? undefined : "Container Insights is not enabled for this cluster"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking ECS clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkEcsContainerInsights(region);
	printSummary(generateSummary(results));
}

export default {
	title: "ECS clusters should use Container Insights",
	description:
		"ECS clusters must enable Container Insights for monitoring metrics, logs, and diagnostics to maintain reliability and performance.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_ECS.12",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkEcsContainerInsights
} satisfies RuntimeTest;
