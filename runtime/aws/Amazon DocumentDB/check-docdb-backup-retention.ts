import { DocDBClient } from "@aws-sdk/client-docdb";
import { getAllDocDBClusters } from "../../utils/aws/get-all-docdb-clusters.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

const MIN_BACKUP_RETENTION_DAYS = 7;

async function checkDocDBBackupRetention(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new DocDBClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const clusters = (await getAllDocDBClusters(client)) ?? [];

		if (clusters.length === 0) {
			results.checks = [
				{
					resourceName: "No DocumentDB Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No DocumentDB clusters found in the region"
				}
			];
			return results;
		}

		for (const cluster of clusters) {
			if (!cluster.DBClusterIdentifier || !cluster.DBClusterArn) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without identifier or ARN"
				});
				continue;
			}

			const retentionPeriod = cluster.BackupRetentionPeriod || 0;
			const isCompliant = retentionPeriod >= MIN_BACKUP_RETENTION_DAYS;

			results.checks.push({
				resourceName: cluster.DBClusterIdentifier,
				resourceArn: cluster.DBClusterArn,
				status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isCompliant
					? undefined
					: `Backup retention period (${retentionPeriod} days) is less than the required ${MIN_BACKUP_RETENTION_DAYS} days`
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking DocumentDB clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkDocDBBackupRetention(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Amazon DocumentDB clusters should have an adequate backup retention period",
	description:
		"Amazon DocumentDB clusters must maintain backup retention periods of at least 7 days to ensure data recovery capabilities.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_DocumentDB.2",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkDocDBBackupRetention,
	serviceName: "Amazon DocumentDB",
	shortServiceName: "docdb"
} satisfies RuntimeTest;
