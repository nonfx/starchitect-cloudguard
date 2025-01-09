import { ElastiCacheClient, type CacheCluster } from "@aws-sdk/client-elasticache";
import { getCacheClusters } from "./elasticache-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkElastiCacheSubnetGroups(
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

		for (const cluster of cacheClusters) {
			if (!cluster.CacheClusterId || !cluster.ARN) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without ID or ARN"
				});
				continue;
			}

			const isUsingDefaultSubnet = cluster.CacheSubnetGroupName === "default";

			results.checks.push({
				resourceName: cluster.CacheClusterId,
				resourceArn: cluster.ARN,
				status: isUsingDefaultSubnet ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: isUsingDefaultSubnet
					? "ElastiCache cluster is using the default subnet group"
					: undefined
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
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkElastiCacheSubnetGroups(region);
	printSummary(generateSummary(results));
}

export default {
	title: "ElastiCache clusters should not use the default subnet group",
	description:
		"ElastiCache clusters must use custom subnet groups instead of default ones to ensure better network security and control.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_ElastiCache.7",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkElastiCacheSubnetGroups,
	serviceName: "Amazon ElastiCache",
	shortServiceName: "elasticache"
} satisfies RuntimeTest;
