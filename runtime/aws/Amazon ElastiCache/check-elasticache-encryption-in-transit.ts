import { ElastiCacheClient, type ReplicationGroup } from "@aws-sdk/client-elasticache";
import { getReplicationGroups } from "../../utils/aws/elasticache-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkElastiCacheEncryptionInTransit(
	region: string = process.env.AWS_REGION || "us-east-1"
): Promise<ComplianceReport> {
	const client = new ElastiCacheClient({ region });
	const results: ComplianceReport = { checks: [] };

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
			if (!group.ReplicationGroupId) {
				results.checks.push({
					resourceName: "Unknown Replication Group",
					status: ComplianceStatus.ERROR,
					message: "Replication group found without ID"
				});
				continue;
			}

			const transitEncryptionEnabled = group.TransitEncryptionEnabled === true;

			results.checks.push({
				resourceName: group.ReplicationGroupId,
				resourceArn: group.ARN,
				status: transitEncryptionEnabled ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: !transitEncryptionEnabled
					? "ElastiCache ReplicationGroup does not have encryption in transit enabled"
					: undefined
			});
		}

		// If no clusters or groups found
		if (results.checks.length === 0) {
			results.checks.push({
				resourceName: "ElastiCache",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No ElastiCache clusters or replication groups found"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "ElastiCache",
			status: ComplianceStatus.ERROR,
			message: `Error checking ElastiCache encryption: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkElastiCacheEncryptionInTransit(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Encryption at Rest and in Transit is configured - in transit",
	description:
		"Enabling encryption at rest and in transit for Amazon ElastiCache helps protect your data when it is stored and transmitted",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_5.3",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkElastiCacheEncryptionInTransit,
	serviceName: "Amazon ElastiCache",
	shortServiceName: "elasticache"
} satisfies RuntimeTest;
