import { ElastiCacheClient, type CacheCluster } from "@aws-sdk/client-elasticache";
import { getCacheClusters } from "./elasticache-utils.js";
import { CloudWatchClient, ListMetricsCommand } from "@aws-sdk/client-cloudwatch";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkElastiCacheMonitoringCompliance(
	region: string = process.env.AWS_REGION || "us-east-1"
): Promise<ComplianceReport> {
	const elasticacheClient = new ElastiCacheClient({ region });
	const cloudwatchClient = new CloudWatchClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all ElastiCache clusters using utility function
		const cacheClusters = await getCacheClusters(elasticacheClient);

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

			// Step 1: Check if CloudWatch metrics are available for the cluster
			const metricsCommand = new ListMetricsCommand({
				Namespace: "AWS/ElastiCache",
				Dimensions: [
					{
						Name: "CacheClusterId",
						Value: cluster.CacheClusterId
					}
				]
			});

			const metricsData = await cloudwatchClient.send(metricsCommand);

			// Step 2: Determine if Enhanced Monitoring is enabled based on the presence of metrics
			const hasMetrics = metricsData.Metrics && metricsData.Metrics.length > 0;

			// Step 3: Check if CloudWatch Logs Export (slowlog) is enabled
			const hasLogging = cluster.LogDeliveryConfigurations?.some(
				config => config.DestinationType === "cloudwatch-logs" && config.LogFormat && config.LogType
			);

			// Step 4: Add compliance checks for Enhanced Monitoring
			results.checks.push({
				resourceName: cluster.CacheClusterId,
				resourceArn: cluster.ARN,
				status: hasMetrics ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasMetrics
					? undefined
					: "ElastiCache cluster does not have Enhanced Monitoring metrics enabled"
			});

			// Step 5: Check for CloudWatch Logs
			results.checks.push({
				resourceName: cluster.CacheClusterId,
				resourceArn: cluster.ARN,
				status: hasLogging ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasLogging
					? undefined
					: "ElastiCache cluster does not have CloudWatch logs enabled"
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
	const results = await checkElastiCacheMonitoringCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Monitoring and Logging is Enabled for ElastiCache",
	description:
		"Implementing monitoring and logging for Amazon ElastiCache allows you to gain visibility into the performance, health, and behavior of your ElastiCache clusters.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_5.6",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkElastiCacheMonitoringCompliance,
	serviceName: "Amazon ElastiCache",
	shortServiceName: "elasticache"
} satisfies RuntimeTest;
