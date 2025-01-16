import { ElastiCacheClient, type ReplicationGroup } from "@aws-sdk/client-elasticache";
import { getReplicationGroups } from "../../utils/aws/elasticache-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkElastiCacheAutoFailover(
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

		for (const group of replicationGroups) {
			if (!group.ReplicationGroupId || !group.ARN) {
				results.checks.push({
					resourceName: "Unknown Replication Group",
					status: ComplianceStatus.ERROR,
					message: "Replication group found without ID or ARN"
				});
				continue;
			}

			results.checks.push({
				resourceName: group.ReplicationGroupId,
				resourceArn: group.ARN,
				status:
					group.AutomaticFailover === "enabled" ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message:
					group.AutomaticFailover !== "enabled"
						? "Automatic failover is not enabled for this replication group"
						: undefined
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking ElastiCache replication groups: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkElastiCacheAutoFailover(region);
	printSummary(generateSummary(results));
}

export default {
	title: "ElastiCache replication groups should have automatic failover enabled",
	description:
		"ElastiCache replication groups must enable automatic failover to ensure high availability and minimize downtime during node failures.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_ElastiCache.3",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkElastiCacheAutoFailover,
	serviceName: "Amazon ElastiCache",
	shortServiceName: "elastiCache"
} satisfies RuntimeTest;
