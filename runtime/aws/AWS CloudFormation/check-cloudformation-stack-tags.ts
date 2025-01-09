import {
	CloudFormationClient,
	ListStacksCommand,
	DescribeStacksCommand
} from "@aws-sdk/client-cloudformation";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkCloudFormationStackTags(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new CloudFormationClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all CloudFormation stacks
		const listResponse = await client.send(new ListStacksCommand({}));

		if (!listResponse.StackSummaries || listResponse.StackSummaries.length === 0) {
			results.checks = [
				{
					resourceName: "No CloudFormation Stacks",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No CloudFormation stacks found in the region"
				}
			];
			return results;
		}

		// Check each stack for tags
		for (const stackSummary of listResponse.StackSummaries) {
			if (!stackSummary.StackName) {
				continue;
			}

			try {
				const describeResponse = await client.send(
					new DescribeStacksCommand({
						StackName: stackSummary.StackName
					})
				);

				const stack = describeResponse.Stacks?.[0];
				if (!stack) continue;

				// Filter out system tags (starting with 'aws:')
				const userTags = stack.Tags?.filter(tag => !tag.Key?.startsWith("aws:")) || [];

				results.checks.push({
					resourceName: stackSummary.StackName,
					resourceArn: stack.StackId,
					status: userTags.length > 0 ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message:
						userTags.length === 0
							? "CloudFormation stack does not have any user-defined tags"
							: undefined
				});
			} catch (error) {
				results.checks.push({
					resourceName: stackSummary.StackName,
					status: ComplianceStatus.ERROR,
					message: `Error checking stack tags: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking CloudFormation stacks: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkCloudFormationStackTags(region);
	printSummary(generateSummary(results));
}

export default {
	title: "CloudFormation stacks should be tagged",
	description:
		"This control checks whether an AWS CloudFormation stack has tags with the specific keys defined in the parameter requiredTagKeys. The control fails if the stack doesn't have any tag keys or if it doesn't have all the keys specified in the parameter requiredTagKeys. If the parameter requiredTagKeys isn't provided, the control only checks for the existence of a tag key and fails if the stack isn't tagged with any key. System tags, which are automatically applied and begin with aws:, are ignored. A tag is a label that you assign to an AWS resource, and it consists of a key and an optional value. You can create tags to categorize resources by purpose, owner, environment, or other criteria. Tags can help you identify, organize, search for, and filter resources. Tagging also helps you track accountable resource owners for actions and notifications. When you use tagging, you can implement attribute-based access control (ABAC) as an authorization strategy, which defines permissions based on tags. You can attach tags to IAM entities (users or roles) and to AWS resources. You can create a single ABAC policy or a separate set of policies for your IAM principals. You can design these ABAC policies to allow operations when the principal's tag matches the resource tag",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFormation.2",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "LOW",
	execute: checkCloudFormationStackTags,
	serviceName: "AWS CloudFormation",
	shortServiceName: "cloudformation"
} satisfies RuntimeTest;
