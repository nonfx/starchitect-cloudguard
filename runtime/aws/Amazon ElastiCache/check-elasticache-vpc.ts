import { ElastiCacheClient, type CacheCluster } from "@aws-sdk/client-elasticache";
import { getCacheClusters } from "./elasticache-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkElastiCacheVpcCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new ElastiCacheClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all ElastiCache clusters using utility function
		const cacheClusters = await getCacheClusters(client);

		if (cacheClusters.length === 0) {
			results.checks.push({
				resourceName: "No ElastiCache Clusters",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No ElastiCache clusters found in the region"
			});
			return results;
		}

		// Check each cluster for VPC configuration
		for (const cluster of cacheClusters) {
			if (!cluster.CacheClusterId) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without ID"
				});
				continue;
			}

			const isVpcEnabled = cluster.CacheSubnetGroupName !== undefined;

			results.checks.push({
				resourceName: cluster.CacheClusterId,
				resourceArn: cluster.ARN,
				status: isVpcEnabled ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isVpcEnabled ? undefined : "ElastiCache cluster is not configured to use a VPC"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking ElastiCache clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkElastiCacheVpcCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Virtual Private Cloud (VPC) is Enabled for ElastiCache",
	description:
		"Implementing VPC security best practices for Amazon ElastiCache involves configuring your Virtual Private Cloud (VPC) and associated resources to enhance the security of your ElastiCache clusters.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_5.5",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkElastiCacheVpcCompliance,
	serviceName: "Amazon ElastiCache",
	shortServiceName: "elasticache"
} satisfies RuntimeTest;
