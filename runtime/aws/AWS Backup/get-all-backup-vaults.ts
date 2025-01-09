import {
	BackupClient,
	ListBackupVaultsCommand,
	type ListBackupVaultsCommandOutput
} from "@aws-sdk/client-backup";

/**
 * Get all backup vaults in a region
 * @param client BackupClient instance
 * @returns Array of backup vaults or undefined if none found
 */
export async function getAllBackupVaults(
	client: BackupClient
): Promise<NonNullable<ListBackupVaultsCommandOutput["BackupVaultList"]> | undefined> {
	try {
		const response = await client.send(new ListBackupVaultsCommand({}));
		return response.BackupVaultList;
	} catch (error) {
		console.error("Error listing backup vaults:", error);
		throw error;
	}
}
