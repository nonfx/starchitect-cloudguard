import {
	BackupClient,
	ListBackupVaultsCommand,
	ListRecoveryPointsByBackupVaultCommand,
	DescribeRecoveryPointCommand
} from "@aws-sdk/client-backup";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkBackupRecoveryPointEncryption(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new BackupClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all backup vaults first
		const vaults = await client.send(new ListBackupVaultsCommand({}));

		if (!vaults.BackupVaultList || vaults.BackupVaultList.length === 0) {
			results.checks = [
				{
					resourceName: "No Backup Vaults",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No backup vaults found in the region"
				}
			];
			return results;
		}

		// Check recovery points in each vault
		for (const vault of vaults.BackupVaultList) {
			if (!vault.BackupVaultName) {
				results.checks.push({
					resourceName: "Unknown Vault",
					status: ComplianceStatus.ERROR,
					message: "Backup vault found without name"
				});
				continue;
			}

			try {
				const recoveryPoints = await client.send(
					new ListRecoveryPointsByBackupVaultCommand({
						BackupVaultName: vault.BackupVaultName
					})
				);

				if (!recoveryPoints.RecoveryPoints || recoveryPoints.RecoveryPoints.length === 0) {
					results.checks.push({
						resourceName: vault.BackupVaultName,
						status: ComplianceStatus.NOTAPPLICABLE,
						message: "No recovery points found in vault"
					});
					continue;
				}

				// Check each recovery point in the vault
				for (const point of recoveryPoints.RecoveryPoints) {
					if (!point.RecoveryPointArn) {
						results.checks.push({
							resourceName: vault.BackupVaultName,
							status: ComplianceStatus.ERROR,
							message: "Recovery point found without ARN"
						});
						continue;
					}

					try {
						const details = await client.send(
							new DescribeRecoveryPointCommand({
								BackupVaultName: vault.BackupVaultName,
								RecoveryPointArn: point.RecoveryPointArn
							})
						);

						const isEncrypted = details.EncryptionKeyArn !== undefined;

						results.checks.push({
							resourceName: point.RecoveryPointArn,
							resourceArn: point.RecoveryPointArn,
							status: isEncrypted ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
							message: isEncrypted ? undefined : "Recovery point is not encrypted at rest"
						});
					} catch (error) {
						results.checks.push({
							resourceName: point.RecoveryPointArn,
							resourceArn: point.RecoveryPointArn,
							status: ComplianceStatus.ERROR,
							message: `Error checking recovery point: ${error instanceof Error ? error.message : String(error)}`
						});
					}
				}
			} catch (error) {
				results.checks.push({
					resourceName: vault.BackupVaultName,
					status: ComplianceStatus.ERROR,
					message: `Error checking vault recovery points: ${error instanceof Error ? error.message : String(error)}`
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
	const results = await checkBackupRecoveryPointEncryption(region);
	printSummary(generateSummary(results));
}

export default {
	title: "AWS Backup recovery points should be encrypted at rest",
	description:
		"This control checks if an AWS Backup recovery point is encrypted at rest. The control fails if the recovery point isn't encrypted at rest. An AWS Backup recovery point refers to a specific copy or snapshot of data that is created as part of a backup process. It represents a particular moment in time when the data was backed up and serves as a restore point in case the original data becomes lost, corrupted, or inaccessible. Encrypting the backup recovery points adds an extra layer of protection against unauthorized access. Encryption is a best practice to protect the confidentiality, integrity, and security of backup data.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_Backup.1",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkBackupRecoveryPointEncryption,
	serviceName: "AWS Backup",
	shortServiceName: "backup"
} satisfies RuntimeTest;
