import { DocDBClient, DescribeDBClusterSnapshotsCommand } from "@aws-sdk/client-docdb";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
async function checkDocDBManualSnapshotCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new DocDBClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const command = new DescribeDBClusterSnapshotsCommand({
			SnapshotType: "manual",
			IncludePublic: true,
			IncludeShared: true
		});

		const response = await client.send(command);
		const snapshots = response.DBClusterSnapshots || [];

		if (snapshots.length === 0) {
			results.checks = [
				{
					resourceName: "No DocumentDB Snapshots",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No manual DocumentDB cluster snapshots found"
				}
			];
			return results;
		}

		for (const snapshot of snapshots) {
			if (!snapshot.DBClusterSnapshotIdentifier || !snapshot.DBClusterSnapshotArn) {
				results.checks.push({
					resourceName: "Unknown Snapshot",
					status: ComplianceStatus.ERROR,
					message: "Snapshot found without identifier or ARN"
				});
				continue;
			}

			// Check if the snapshot is publicly accessible
			const isPublic = (snapshot as any).AttributeValues?.includes("all") ?? false;

			const snapshotId = snapshot.DBClusterSnapshotIdentifier.includes(":")
				? snapshot.DBClusterSnapshotIdentifier.split(":").pop()
				: snapshot.DBClusterSnapshotIdentifier;

			if (!snapshotId) {
				results.checks.push({
					resourceName: snapshot.DBClusterSnapshotIdentifier,
					resourceArn: snapshot.DBClusterSnapshotArn,
					status: ComplianceStatus.ERROR,
					message: "Could not determine snapshot identifier"
				});
				continue;
			}

			results.checks.push({
				resourceName: snapshotId,
				resourceArn: snapshot.DBClusterSnapshotArn,
				status: isPublic ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: isPublic ? "DocumentDB cluster snapshot is publicly accessible" : undefined
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "DocumentDB Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking DocumentDB snapshots: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkDocDBManualSnapshotCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Amazon DocumentDB manual cluster snapshots should not be public",
	description:
		"This control checks if DocumentDB manual cluster snapshots are public. Public snapshots can expose sensitive data to unauthorized users and should be restricted.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_DocumentDB.3",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "CRITICAL",
	execute: checkDocDBManualSnapshotCompliance,
	serviceName: "Amazon DocumentDB",
	shortServiceName: "docdb"
} satisfies RuntimeTest;
