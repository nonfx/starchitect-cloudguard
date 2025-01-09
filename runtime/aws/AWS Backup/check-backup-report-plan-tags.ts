import { BackupClient, ListTagsCommand } from "@aws-sdk/client-backup";
import { getAllReportPlans } from "./get-all-report-plans.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkBackupReportPlanTags(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new BackupClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all backup report plans using helper with pagination
		const reportPlans = await getAllReportPlans(client);

		if (!reportPlans || reportPlans.length === 0) {
			results.checks = [
				{
					resourceName: "No Backup Report Plans",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No backup report plans found in the region"
				}
			];
			return results;
		}

		// Check each report plan for tags
		for (const plan of reportPlans) {
			if (!plan.ReportPlanName || !plan.ReportPlanArn) {
				results.checks.push({
					resourceName: "Unknown Report Plan",
					status: ComplianceStatus.ERROR,
					message: "Report plan found without name or ARN"
				});
				continue;
			}

			try {
				// Get tags for the report plan
				const tagsResponse = await client.send(
					new ListTagsCommand({
						ResourceArn: plan.ReportPlanArn
					})
				);

				const tags = tagsResponse.Tags || {};
				const hasUserDefinedTags = Object.keys(tags).some(key => !key.startsWith("aws:"));

				results.checks.push({
					resourceName: plan.ReportPlanName,
					resourceArn: plan.ReportPlanArn,
					status: hasUserDefinedTags ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: hasUserDefinedTags
						? undefined
						: "Backup report plan does not have any user-defined tags"
				});
			} catch (error) {
				results.checks.push({
					resourceName: plan.ReportPlanName,
					resourceArn: plan.ReportPlanArn,
					status: ComplianceStatus.ERROR,
					message: `Error checking tags: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking backup report plans: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkBackupReportPlanTags(region);
	printSummary(generateSummary(results));
}

export default {
	title: "AWS Backup report plans should be tagged",
	description:
		"This control checks whether an AWS Backup report plan has user-defined tags. The control fails if the report plan does not have any user-defined tag keys. System tags, which are automatically applied and begin with aws:, are ignored.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_Backup.4",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "LOW",
	execute: checkBackupReportPlanTags,
	serviceName: "AWS Backup",
	shortServiceName: "backup"
} satisfies RuntimeTest;
