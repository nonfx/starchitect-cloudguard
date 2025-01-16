import { ElastiCacheClient, type CacheCluster } from "@aws-sdk/client-elasticache";
import { getCacheClusters } from "../../utils/aws/elasticache-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkElastiCacheAutoMinorVersionUpgrade(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new ElastiCacheClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const clusters = await getCacheClusters(client);

		if (clusters.length === 0) {
			results.checks.push({
				resourceName: "No ElastiCache Clusters",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No ElastiCache clusters found in the region"
			});
			return results;
		}

		for (const cluster of clusters) {
			if (!cluster.CacheClusterId || !cluster.ARN) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without ID or ARN"
				});
				continue;
			}

			const isAutoUpgradeEnabled = cluster.AutoMinorVersionUpgrade === true;

			results.checks.push({
				resourceName: cluster.CacheClusterId,
				resourceArn: cluster.ARN,
				status: isAutoUpgradeEnabled ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isAutoUpgradeEnabled
					? undefined
					: "Auto minor version upgrade is not enabled for the ElastiCache cluster"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "ElastiCache Check",
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
	const results = await checkElastiCacheAutoMinorVersionUpgrade(region);
	printSummary(generateSummary(results));
}

export default {
	title: "ElastiCache Redis clusters should have auto minor version upgrades enabled",
	description:
		"ElastiCache Redis clusters must enable automatic minor version upgrades for enhanced security and bug fixes.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_ElastiCache.2",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkElastiCacheAutoMinorVersionUpgrade,
	serviceName: "Amazon ElastiCache",
	shortServiceName: "elastiCache"
} satisfies RuntimeTest;
