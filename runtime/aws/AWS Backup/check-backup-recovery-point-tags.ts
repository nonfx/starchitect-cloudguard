import {
	BackupClient,
	ListRecoveryPointsByBackupVaultCommand,
	type RecoveryPointByBackupVault
} from "@aws-sdk/client-backup";
import { getAllBackupVaults } from "./get-all-backup-vaults.js";

// Extend the RecoveryPointByBackupVault type to include Tags
interface RecoveryPointWithTags extends RecoveryPointByBackupVault {
	Tags?: Record<string, string>;
}
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

function hasUserDefinedTags(tags: Record<string, string> | undefined): boolean {
	if (!tags) return false;
	return Object.keys(tags).some(key => !key.startsWith("aws:"));
}

async function checkBackupRecoveryPointTags(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new BackupClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all backup vaults using helper
		const vaults = await getAllBackupVaults(client);

		if (!vaults || vaults.length === 0) {
			results.checks = [
				{
					resourceName: "No Backup Vaults",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No AWS Backup vaults found in the region"
				}
			];
			return results;
		}

		// Check recovery points in each vault
		for (const vault of vaults) {
			if (!vault.BackupVaultName) continue;

			try {
				const recoveryPoints = await client.send(
					new ListRecoveryPointsByBackupVaultCommand({
						BackupVaultName: vault.BackupVaultName
					})
				);

				if (!recoveryPoints.RecoveryPoints || recoveryPoints.RecoveryPoints.length === 0) {
					results.checks.push({
						resourceName: vault.BackupVaultName,
						resourceArn: vault.BackupVaultArn,
						status: ComplianceStatus.NOTAPPLICABLE,
						message: "No recovery points found in vault"
					});
					continue;
				}

				for (const point of (recoveryPoints.RecoveryPoints || []) as RecoveryPointWithTags[]) {
					if (!point.RecoveryPointArn) continue;

					const hasTags = hasUserDefinedTags(point.Tags);

					results.checks.push({
						resourceName: point.RecoveryPointArn,
						resourceArn: point.RecoveryPointArn,
						status: hasTags ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: hasTags ? undefined : "Recovery point has no user-defined tags"
					});
				}
			} catch (error) {
				results.checks.push({
					resourceName: vault.BackupVaultName,
					resourceArn: vault.BackupVaultArn,
					status: ComplianceStatus.ERROR,
					message: `Error checking recovery points: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking backup vaults: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkBackupRecoveryPointTags(region);
	printSummary(generateSummary(results));
}

export default {
	title: "AWS Backup recovery points should be tagged",
	description:
		"This control checks whether an AWS Backup recovery point has any user-defined tags. The control fails if the recovery point doesn't have any user-defined tags. System tags, which are automatically applied and begin with aws:, are ignored.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_Backup.2",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkBackupRecoveryPointTags,
	serviceName: "AWS Backup",
	shortServiceName: "backup"
} satisfies RuntimeTest;
