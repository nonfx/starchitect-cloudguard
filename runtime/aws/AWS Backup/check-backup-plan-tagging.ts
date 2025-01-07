import { BackupClient, ListBackupPlansCommand, ListTagsCommand } from "@aws-sdk/client-backup";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkBackupPlanTagging(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new BackupClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all backup plans
		const response = await client.send(new ListBackupPlansCommand({}));

		if (!response.BackupPlansList || response.BackupPlansList.length === 0) {
			results.checks = [
				{
					resourceName: "No Backup Plans",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No backup plans found in the region"
				}
			];
			return results;
		}

		// Check each backup plan for user-defined tags
		for (const plan of response.BackupPlansList) {
			if (!plan.BackupPlanName || !plan.BackupPlanArn) {
				results.checks.push({
					resourceName: "Unknown Backup Plan",
					status: ComplianceStatus.ERROR,
					message: "Backup plan found without name or ARN"
				});
				continue;
			}

			// Get tags for the backup plan
			const tagsResponse = await client.send(
				new ListTagsCommand({
					ResourceArn: plan.BackupPlanArn
				})
			);

			const tags = tagsResponse.Tags || {};
			const hasUserDefinedTags = Object.keys(tags).some(key => {
				if (!key.startsWith("aws:")) {
					return true;
				}
				return false;
			});

			results.checks.push({
				resourceName: plan.BackupPlanName,
				resourceArn: plan.BackupPlanArn,
				status: hasUserDefinedTags ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasUserDefinedTags ? undefined : "Backup plan does not have any user-defined tags"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking backup plans: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkBackupPlanTagging(region);
	printSummary(generateSummary(results));
}

export default {
	title: "AWS Backup backup plans should be tagged",
	description:
		"This control checks whether an AWS Backup backup plan has user-defined tags. The control fails if the backup plan doesn't have any user-defined tag keys. System tags, which are automatically applied and begin with aws:, are ignored.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_Backup.5",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "LOW",
	execute: checkBackupPlanTagging,
	serviceName: "AWS Backup",
	shortServiceName: "backup"
} satisfies RuntimeTest;
