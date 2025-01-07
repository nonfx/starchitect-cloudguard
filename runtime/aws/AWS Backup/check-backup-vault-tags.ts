import { BackupClient, ListBackupVaultsCommand, ListTagsCommand } from "@aws-sdk/client-backup";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkBackupVaultTags(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new BackupClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all backup vaults
		const vaultsResponse = await client.send(new ListBackupVaultsCommand({}));

		if (!vaultsResponse.BackupVaultList || vaultsResponse.BackupVaultList.length === 0) {
			results.checks = [
				{
					resourceName: "No Backup Vaults",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No AWS Backup vaults found in the region"
				}
			];
			return results;
		}

		// Check tags for each vault
		for (const vault of vaultsResponse.BackupVaultList) {
			if (!vault.BackupVaultName || !vault.BackupVaultArn) {
				results.checks.push({
					resourceName: "Unknown Vault",
					status: ComplianceStatus.ERROR,
					message: "Backup vault found without name or ARN"
				});
				continue;
			}

			try {
				// Get tags for the vault
				const tagsResponse = await client.send(
					new ListTagsCommand({
						ResourceArn: vault.BackupVaultArn
					})
				);

				// Check for user-defined tags (non-aws: prefixed)
				const hasUserTags = Object.keys(tagsResponse.Tags || {}).some(
					key => !key.startsWith("aws:")
				);

				results.checks.push({
					resourceName: vault.BackupVaultName,
					resourceArn: vault.BackupVaultArn,
					status: hasUserTags ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: hasUserTags ? undefined : "Backup vault does not have any user-defined tags"
				});
			} catch (error) {
				results.checks.push({
					resourceName: vault.BackupVaultName,
					resourceArn: vault.BackupVaultArn,
					status: ComplianceStatus.ERROR,
					message: `Error checking vault tags: ${error instanceof Error ? error.message : String(error)}`
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
	const results = await checkBackupVaultTags(region);
	printSummary(generateSummary(results));
}

export default {
	title: "AWS Backup vaults should be tagged",
	description:
		"This control checks whether an AWS Backup vault has user-defined tags. The control fails if the backup vault doesn't have any user-defined tag keys. System tags, which are automatically applied and begin with aws:, are ignored.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_Backup.3",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "LOW",
	execute: checkBackupVaultTags,
	serviceName: "AWS Backup",
	shortServiceName: "backup"
} satisfies RuntimeTest;
