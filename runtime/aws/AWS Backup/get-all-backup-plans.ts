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
		const backupPlans: NonNullable<ListBackupPlansCommandOutput["BackupPlansList"]> = [];
		let nextToken: string | undefined;

		do {
			const response = await client.send(
				new ListBackupPlansCommand({
					NextToken: nextToken
				})
			);

			if (response.BackupPlansList) {
				backupPlans.push(...response.BackupPlansList);
			}

			nextToken = response.NextToken;
		} while (nextToken);

		return backupPlans.length > 0 ? backupPlans : undefined;
	} catch (error) {
		console.error("Error listing backup plans:", error);
		throw error;
	}
}
