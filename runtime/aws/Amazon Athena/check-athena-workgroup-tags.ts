import {
	AthenaClient,
	ListWorkGroupsCommand,
	ListTagsForResourceCommand
} from "@aws-sdk/client-athena";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkAthenaWorkgroupTags(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new AthenaClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let nextToken: string | undefined;
		let workgroupsFound = false;

		do {
			// Get all Athena workgroups
			const listCommand = new ListWorkGroupsCommand({
				NextToken: nextToken
			});
			const response = await client.send(listCommand);

			if (!response.WorkGroups || response.WorkGroups.length === 0) {
				if (!workgroupsFound) {
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

			workgroupsFound = true;

			// Check tags for each workgroup
			for (const workgroup of response.WorkGroups) {
				if (!workgroup.Name) {
					results.checks.push({
						resourceName: "Unknown Workgroup",
						status: ComplianceStatus.ERROR,
						message: "Workgroup found without name"
					});
					continue;
				}

				try {
					// Get tags for the workgroup
					const tagsCommand = new ListTagsForResourceCommand({
						ResourceARN: `arn:aws:athena:${region}:${process.env.AWS_ACCOUNT_ID}:workgroup/${workgroup.Name}`
					});
					const tagsResponse = await client.send(tagsCommand);

					// Filter out system tags (starting with 'aws:')
					const userTags = tagsResponse.Tags?.filter(tag => !tag.Key?.startsWith("aws:")) || [];

					results.checks.push({
						resourceName: workgroup.Name,
						status: userTags.length > 0 ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message:
							userTags.length === 0 ? "Workgroup does not have any non-system tags" : undefined
					});
				} catch (error) {
					results.checks.push({
						resourceName: workgroup.Name,
						status: ComplianceStatus.ERROR,
						message: `Error checking tags: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			}

			nextToken = response.NextToken;
		} while (nextToken);
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
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
	const results = await checkAthenaWorkgroupTags(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Athena workgroups should be tagged",
	description:
		"This control checks whether an Amazon Athena workgroup has tags with the specific keys defined in the parameter requiredTagKeys. The control fails if the workgroup doesn't have any tag keys or if it doesn't have all the keys specified in the parameter requiredTagKeys. If the parameter requiredTagKeys isn't provided, the control only checks for the existence of a tag key and fails if the workgroup isn't tagged with any key. System tags, which are automatically applied and begin with aws:, are ignored. A tag is a label that you assign to an AWS resource, and it consists of a key and an optional value. You can create tags to categorize resources by purpose, owner, environment, or other criteria. Tags can help you identify, organize, search for, and filter resources. Tagging also helps you track accountable resource owners for actions and notifications. When you use tagging, you can implement attribute-based access control (ABAC) as an authorization strategy, which defines permissions based on tags. You can attach tags to IAM entities (users or roles) and to AWS resources. You can create a single ABAC policy or a separate set of policies for your IAM principals. You can design these ABAC policies to allow operations when the principal's tag matches the resource tag",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_Athena.3",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "LOW",
	execute: checkAthenaWorkgroupTags,
	serviceName: "Amazon Athena",
	shortServiceName: "athena"
} satisfies RuntimeTest;
