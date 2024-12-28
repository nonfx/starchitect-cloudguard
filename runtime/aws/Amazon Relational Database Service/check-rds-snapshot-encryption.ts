import {
	RDSClient,
	DescribeDBSnapshotsCommand,
	DescribeDBClusterSnapshotsCommand
} from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkRdsSnapshotEncryption(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Check DB snapshots
		const dbSnapshots = await client.send(new DescribeDBSnapshotsCommand({}));
		if (dbSnapshots.DBSnapshots) {
			for (const snapshot of dbSnapshots.DBSnapshots) {
				if (!snapshot.DBSnapshotIdentifier || !snapshot.DBSnapshotArn) {
					results.checks.push({
						resourceName: "Unknown DB Snapshot",
						status: ComplianceStatus.ERROR,
						message: "DB Snapshot missing identifier or ARN"
					});
					continue;
				}

				results.checks.push({
					resourceName: snapshot.DBSnapshotIdentifier,
					resourceArn: snapshot.DBSnapshotArn,
					status: snapshot.Encrypted ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: snapshot.Encrypted ? undefined : "DB snapshot is not encrypted at rest"
				});
			}
		}

		// Check DB cluster snapshots
		const clusterSnapshots = await client.send(new DescribeDBClusterSnapshotsCommand({}));
		if (clusterSnapshots.DBClusterSnapshots) {
			for (const snapshot of clusterSnapshots.DBClusterSnapshots) {
				if (!snapshot.DBClusterSnapshotIdentifier || !snapshot.DBClusterSnapshotArn) {
					results.checks.push({
						resourceName: "Unknown Cluster Snapshot",
						status: ComplianceStatus.ERROR,
						message: "DB Cluster Snapshot missing identifier or ARN"
					});
					continue;
				}

				results.checks.push({
					resourceName: snapshot.DBClusterSnapshotIdentifier,
					resourceArn: snapshot.DBClusterSnapshotArn,
					status: snapshot.StorageEncrypted ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: snapshot.StorageEncrypted
						? undefined
						: "DB cluster snapshot is not encrypted at rest"
				});
			}
		}

		// If no snapshots found
		if (results.checks.length === 0) {
			results.checks.push({
				resourceName: "No RDS Snapshots",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No RDS snapshots found in the region"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "RDS Snapshot Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking RDS snapshots: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkRdsSnapshotEncryption(region);
	printSummary(generateSummary(results));
}

export default {
	title: "RDS cluster snapshots and database snapshots should be encrypted at rest",
	description:
		"This control checks if RDS DB snapshots and cluster snapshots are encrypted at rest. The control fails if snapshots are not encrypted.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.4",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsSnapshotEncryption
} satisfies RuntimeTest;
