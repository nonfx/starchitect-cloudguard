import {
	BackupClient,
	ListReportPlansCommand,
	type ListReportPlansCommandOutput,
	type ReportPlan
} from "@aws-sdk/client-backup";

/**
 * Get all report plans in a region with pagination
 * @param client BackupClient instance
 * @returns Array of report plans or undefined if none found
 */
export async function getAllReportPlans(client: BackupClient): Promise<ReportPlan[] | undefined> {
	try {
		const reportPlans: ReportPlan[] = [];
		let nextToken: string | undefined;

		do {
			const response: ListReportPlansCommandOutput = await client.send(
				new ListReportPlansCommand({
					NextToken: nextToken
				})
			);

			if (response.ReportPlans) {
				reportPlans.push(...response.ReportPlans);
			}

			nextToken = response.NextToken;
		} while (nextToken);

		return reportPlans.length > 0 ? reportPlans : undefined;
	} catch (error) {
		console.error("Error listing report plans:", error);
		throw error;
	}
}
