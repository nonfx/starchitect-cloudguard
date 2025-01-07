import { AthenaClient, ListWorkGroupsCommand, GetWorkGroupCommand } from "@aws-sdk/client-athena";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkAthenaWorkgroupLogging(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new AthenaClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let nextToken: string | undefined;
		let workgroupFound = false;

		do {
			// Get list of all workgroups
			const listCommand = new ListWorkGroupsCommand({
				NextToken: nextToken
			});
			const response = await client.send(listCommand);

			if (!response.WorkGroups || response.WorkGroups.length === 0) {
				if (!workgroupFound) {
					results.checks = [
						{
							resourceName: "No Athena Workgroups",
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "No Athena workgroups found in the region"
						}
					];
					return results;
				}
				break;
			}

			// Check each workgroup's configuration
			for (const workgroup of response.WorkGroups) {
				workgroupFound = true;
				const workgroupName = workgroup.Name || "Unknown Workgroup";

				try {
					const detailCommand = new GetWorkGroupCommand({
						WorkGroup: workgroupName
					});
					const details = await client.send(detailCommand);

					const isLoggingEnabled =
						details.WorkGroup?.Configuration?.PublishCloudWatchMetricsEnabled;

					results.checks.push({
						resourceName: workgroupName,
						status: isLoggingEnabled ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: isLoggingEnabled
							? undefined
							: "CloudWatch metrics logging is not enabled for this workgroup"
					});
				} catch (error) {
					results.checks.push({
						resourceName: workgroupName,
						status: ComplianceStatus.ERROR,
						message: `Error checking workgroup configuration: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			}

			nextToken = response.NextToken;
		} while (nextToken);
	} catch (error) {
		results.checks = [
			{
				resourceName: "Athena Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Athena workgroups: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkAthenaWorkgroupLogging(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Athena workgroups should have logging enabled",
	description:
		"This control checks whether Amazon Athena workgroups have CloudWatch metrics logging enabled. Logging helps track query metrics for security monitoring and compliance purposes.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_Athena.4",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkAthenaWorkgroupLogging,
	serviceName: "Amazon Athena",
	shortServiceName: "athena"
} satisfies RuntimeTest;
