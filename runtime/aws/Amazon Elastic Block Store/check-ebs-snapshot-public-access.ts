import {
	EC2Client,
	DescribeSnapshotsCommand,
	GetEbsEncryptionByDefaultCommand
} from "@aws-sdk/client-ec2";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkEbsSnapshotPublicAccess(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all EBS snapshots owned by the account with pagination
		let nextToken: string | undefined;
		let allSnapshots: any[] = [];

		do {
			const snapshots = await client.send(
				new DescribeSnapshotsCommand({
					OwnerIds: ["self"],
					NextToken: nextToken
				})
			);

			if (snapshots.Snapshots) {
				allSnapshots = allSnapshots.concat(snapshots.Snapshots);
			}

			nextToken = snapshots.NextToken;
		} while (nextToken);

		if (allSnapshots.length === 0) {
			results.checks = [
				{
					resourceName: "No EBS Snapshots",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No EBS snapshots found in the region"
				}
			];
			return results;
		}

		// Check each snapshot's permissions
		for (const snapshot of allSnapshots) {
			if (!snapshot.SnapshotId) {
				results.checks.push({
					resourceName: "Unknown Snapshot",
					status: ComplianceStatus.ERROR,
					message: "Snapshot found without ID"
				});
				continue;
			}

			try {
				const snapshotWithPerms = snapshot as {
					CreateVolumePermissions?: Array<{ Group?: string }>;
				};
				const isPublic = snapshotWithPerms.CreateVolumePermissions?.some(
					(permission: { Group?: string }) => permission.Group === "all"
				);

				results.checks.push({
					resourceName: snapshot.SnapshotId,
					status: isPublic ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
					message: isPublic ? "EBS snapshot has public access enabled" : undefined
				});
			} catch (error) {
				results.checks.push({
					resourceName: snapshot.SnapshotId,
					status: ComplianceStatus.ERROR,
					message: `Error checking snapshot permissions: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking EBS snapshots: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION || "ap-southeast-1";
	const results = await checkEbsSnapshotPublicAccess(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon Elastic Block Store",
	shortServiceName: "ebs",
	title: "Ensure Public Access to EBS Snapshots is Disabled",
	description:
		"To protect your data, ensure that public access to EBS snapshots is properly managed.",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.2.2",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkEbsSnapshotPublicAccess
} satisfies RuntimeTest;
