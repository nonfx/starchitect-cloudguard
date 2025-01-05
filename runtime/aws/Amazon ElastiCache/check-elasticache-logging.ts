import { ElastiCacheClient, type ReplicationGroup } from "@aws-sdk/client-elasticache";
import { getReplicationGroups } from "./elasticache-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkElastiCacheLoggingCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new ElastiCacheClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const replicationGroups = await getReplicationGroups(client);

		if (replicationGroups.length === 0) {
			results.checks.push({
				resourceName: "No ElastiCache Replication Groups",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No ElastiCache replication groups found in the region"
			});
			return results;
		}

		for (const replicationGroup of replicationGroups) {
			if (!replicationGroup.ReplicationGroupId) {
				results.checks.push({
					resourceName: "Unknown Replication Group",
					status: ComplianceStatus.ERROR,
					message: "Replication group found without ID"
				});
				continue;
			}

			const hasLogging =
				replicationGroup.LogDeliveryConfigurations &&
				replicationGroup.LogDeliveryConfigurations.length > 0 &&
				replicationGroup.LogDeliveryConfigurations.some(
					config => config.DestinationType && config.DestinationDetails
				);

			results.checks.push({
				resourceName: replicationGroup.ReplicationGroupId,
				resourceArn: replicationGroup.ARN,
				status: hasLogging ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasLogging ? undefined : "Audit logging is not enabled for the replication group"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "ElastiCache Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking ElastiCache replication groups: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkElastiCacheLoggingCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Audit Logging is Enabled",
	description:
		"To manage your enterprise caching solution, it is important that you know how your clusters are performing and the resources they are consuming. It is also important that you know the events that are being generated and the costs of your deployment. Amazon CloudWatch provides metrics for monitoring your cache performance. In addition, cost allocation tags help you monitor and manage costs",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_5.9",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkElastiCacheLoggingCompliance,
	serviceName: "Amazon ElastiCache",
	shortServiceName: "elasticache"
} satisfies RuntimeTest;
