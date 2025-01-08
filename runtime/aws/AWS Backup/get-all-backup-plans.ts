import {
	BackupClient,
	ListBackupPlansCommand,
	type ListBackupPlansCommandOutput
} from "@aws-sdk/client-backup";

/**
 * Get all backup plans in a region
 * @param client BackupClient instance
 * @returns Array of backup plans or undefined if none found
 */
export async function getAllBackupPlans(
	client: BackupClient
): Promise<NonNullable<ListBackupPlansCommandOutput["BackupPlansList"]> | undefined> {
	try {
		const response = await client.send(new ListBackupPlansCommand({}));
		return response.BackupPlansList;
	} catch (error) {
		console.error("Error listing backup plans:", error);
		throw error;
	}
}
