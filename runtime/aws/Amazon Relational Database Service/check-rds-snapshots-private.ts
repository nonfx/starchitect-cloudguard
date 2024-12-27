import {
	RDSClient,
	DescribeDBSnapshotsCommand,
	DescribeDBClusterSnapshotsCommand,
	DescribeDBSnapshotAttributesCommand,
	DescribeDBClusterSnapshotAttributesCommand
} from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkRdsSnapshotsPrivate(region: string = "us-east-1"): Promise<ComplianceReport> {
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
					continue;
				}

				try {
					const attributes = await client.send(
						new DescribeDBSnapshotAttributesCommand({
							DBSnapshotIdentifier: snapshot.DBSnapshotIdentifier
						})
					);

					const restoreAttribute =
						attributes.DBSnapshotAttributesResult?.DBSnapshotAttributes?.find(
							attr => attr.AttributeName === "restore"
						);
					const isPublic = restoreAttribute?.AttributeValues?.includes("all");

					results.checks.push({
						resourceName: snapshot.DBSnapshotIdentifier,
						resourceArn: snapshot.DBSnapshotArn,
						status: isPublic ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
						message: isPublic ? "RDS DB snapshot is publicly accessible" : undefined
					});
				} catch (error) {
					results.checks.push({
						resourceName: snapshot.DBSnapshotIdentifier,
						resourceArn: snapshot.DBSnapshotArn,
						status: ComplianceStatus.ERROR,
						message: `Error checking snapshot attributes: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			}
		}

		// Check DB cluster snapshots
		const clusterSnapshots = await client.send(new DescribeDBClusterSnapshotsCommand({}));
		if (clusterSnapshots.DBClusterSnapshots) {
			for (const snapshot of clusterSnapshots.DBClusterSnapshots) {
				if (!snapshot.DBClusterSnapshotIdentifier || !snapshot.DBClusterSnapshotArn) {
					continue;
				}

				try {
					const attributes = await client.send(
						new DescribeDBClusterSnapshotAttributesCommand({
							DBClusterSnapshotIdentifier: snapshot.DBClusterSnapshotIdentifier
						})
					);

					console.log(attributes);

					const restoreAttribute =
						attributes.DBClusterSnapshotAttributesResult?.DBClusterSnapshotAttributes?.find(
							attr => attr.AttributeName === "restore"
						);
					const isPublic = restoreAttribute?.AttributeValues?.includes("all");

					results.checks.push({
						resourceName: snapshot.DBClusterSnapshotIdentifier,
						resourceArn: snapshot.DBClusterSnapshotArn,
						status: isPublic ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
						message: isPublic ? "RDS cluster snapshot is publicly accessible" : undefined
					});
				} catch (error) {
					results.checks.push({
						resourceName: snapshot.DBClusterSnapshotIdentifier,
						resourceArn: snapshot.DBClusterSnapshotArn,
						status: ComplianceStatus.ERROR,
						message: `Error checking cluster snapshot attributes: ${error instanceof Error ? error.message : String(error)}`
					});
				}
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
			resourceName: "RDS Snapshots Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking RDS snapshots: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION;
	const results = await checkRdsSnapshotsPrivate(region);
	printSummary(generateSummary(results));
}

export default {
	title: "RDS snapshot should be private",
	description:
		"RDS snapshots must be private and not publicly accessible to prevent unauthorized data exposure and maintain security compliance.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.1",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsSnapshotsPrivate
} satisfies RuntimeTest;
