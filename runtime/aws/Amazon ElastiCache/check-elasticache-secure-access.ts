import { ElastiCacheClient, type ReplicationGroup } from "@aws-sdk/client-elasticache";
import { getReplicationGroups } from "./elasticache-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkElastiCacheSecureAccess(
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

			const hasAuthToken = !!group.AuthTokenEnabled;
			const hasEncryption = !!group.TransitEncryptionEnabled;
			const isCompliant = hasAuthToken && hasEncryption;

			const messages: string[] = [];
			if (!hasAuthToken) {
				messages.push("Authentication is not enabled");
			}
			if (!hasEncryption) {
				messages.push("Transit encryption is not enabled");
			}

			results.checks.push({
				resourceName: group.ReplicationGroupId,
				resourceArn: group.ARN,
				status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: messages.length > 0 ? messages.join("; ") : undefined
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
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkElastiCacheSecureAccess(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Secure Access to ElastiCache",
	description:
		"Securing access to Amazon ElastiCache involves implementing appropriate authentication and authorization mechanisms.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_5.1",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkElastiCacheSecureAccess,
	serviceName: "Amazon ElastiCache",
	shortServiceName: "elasticache"
} satisfies RuntimeTest;
