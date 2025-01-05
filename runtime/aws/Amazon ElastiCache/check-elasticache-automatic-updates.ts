import { ElastiCacheClient, type CacheCluster } from "@aws-sdk/client-elasticache";
import { getCacheClusters } from "./elasticache-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkElastiCacheAutomaticUpdates(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new ElastiCacheClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
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
			if (!cluster.CacheClusterId) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without ID"
				});
				continue;
			}

			const isAutoUpdateEnabled = cluster.AutoMinorVersionUpgrade === true;

			results.checks.push({
				resourceName: cluster.CacheClusterId,
				resourceArn: cluster.ARN,
				status: isAutoUpdateEnabled ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isAutoUpdateEnabled
					? undefined
					: "Automatic minor version upgrades are not enabled for this cluster"
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
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkElastiCacheAutomaticUpdates(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Automatic Updates and Patching are Enabled",
	description:
		"Enabling automatic updates and patching for Amazon ElastiCache ensures that your ElastiCache clusters run the latest software versions with important security fixes and enhancements.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_5.4",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkElastiCacheAutomaticUpdates,
	serviceName: "Amazon ElastiCache",
	shortServiceName: "elasticache"
} satisfies RuntimeTest;
