import { NeptuneClient, DescribeDBClusterSnapshotsCommand } from "@aws-sdk/client-neptune";

import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkNeptuneSnapshotsEncryption(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new NeptuneClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all Neptune DB cluster snapshots
		const command = new DescribeDBClusterSnapshotsCommand({});
		const response = await client.send(command);

		if (!response.DBClusterSnapshots || response.DBClusterSnapshots.length === 0) {
			results.checks = [
				{
					resourceName: "No Neptune Snapshots",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Neptune DB cluster snapshots found in the region"
				}
			];
			return results;
		}

		// Check each snapshot for encryption
		for (const snapshot of response.DBClusterSnapshots) {
			if (!snapshot.DBClusterSnapshotIdentifier || !snapshot.DBClusterSnapshotArn) {
				results.checks.push({
					resourceName: "Unknown Snapshot",
					status: ComplianceStatus.ERROR,
					message: "Snapshot found without identifier or ARN"
				});
				continue;
			}

			results.checks.push({
				resourceName: snapshot.DBClusterSnapshotIdentifier,
				resourceArn: snapshot.DBClusterSnapshotArn,
				status: snapshot.StorageEncrypted ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: snapshot.StorageEncrypted
					? undefined
					: "Neptune DB cluster snapshot is not encrypted at rest"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Neptune Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Neptune snapshots: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkNeptuneSnapshotsEncryption(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Neptune DB cluster snapshots should be encrypted at rest",
	description:
		"This control checks if Neptune DB cluster snapshots are encrypted at rest to protect data confidentiality and meet security compliance requirements.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_Neptune.6",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkNeptuneSnapshotsEncryption,
	serviceName: "Amazon Relational Database Service"
} satisfies RuntimeTest;
