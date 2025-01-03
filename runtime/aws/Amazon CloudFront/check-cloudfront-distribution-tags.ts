import {
	CloudFrontClient,
	ListDistributionsCommand,
	ListTagsForResourceCommand
} from "@aws-sdk/client-cloudfront";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkCloudFrontDistributionTags(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new CloudFrontClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all CloudFront distributions
		const distributions = await client.send(new ListDistributionsCommand({}));

		if (
			!distributions.DistributionList?.Items ||
			distributions.DistributionList.Items.length === 0
		) {
			results.checks = [
				{
					resourceName: "No CloudFront Distributions",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No CloudFront distributions found"
				}
			];
			return results;
		}

		// Check tags for each distribution
		for (const distribution of distributions.DistributionList.Items) {
			if (!distribution.Id || !distribution.ARN) {
				results.checks.push({
					resourceName: "Unknown Distribution",
					status: ComplianceStatus.ERROR,
					message: "Distribution found without ID or ARN"
				});
				continue;
			}

			try {
				const tags = await client.send(
					new ListTagsForResourceCommand({
						Resource: distribution.ARN
					})
				);

				// Filter out system tags (aws:)
				const userTags = tags.Tags?.Items?.filter(tag => !tag.Key?.startsWith("aws:")) || [];

				results.checks.push({
					resourceName: distribution.Id,
					resourceArn: distribution.ARN,
					status: userTags.length > 0 ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message:
						userTags.length === 0 ? "CloudFront distribution has no user-defined tags" : undefined
				});
			} catch (error) {
				results.checks.push({
					resourceName: distribution.Id,
					resourceArn: distribution.ARN,
					status: ComplianceStatus.ERROR,
					message: `Error checking tags: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "CloudFront Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking CloudFront distributions: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkCloudFrontDistributionTags(region);
	printSummary(generateSummary(results));
}

export default {
	title: "CloudFront distributions should be tagged",
	description:
		"This control checks whether an Amazon CloudFront distribution has tags with the specific keys defined in the parameter requiredTagKeys. The control fails if the distribution doesn't have any tag keys or if it doesn't have all the keys specified in the parameter requiredTagKeys. If the parameter requiredTagKeys isn't provided, the control only checks for the existence of a tag key and fails if the distribution isn't tagged with any key. System tags, which are automatically applied and begin with aws:, are ignored. A tag is a label that you assign to an AWS resource, and it consists of a key and an optional value. You can create tags to categorize resources by purpose, owner, environment, or other criteria. Tags can help you identify, organize, search for, and filter resources. Tagging also helps you track accountable resource owners for actions and notifications. When you use tagging, you can implement attribute-based access control (ABAC) as an authorization strategy, which defines permissions based on tags. You can attach tags to IAM entities (users or roles) and to AWS resources. You can create a single ABAC policy or a separate set of policies for your IAM principals. You can design these ABAC policies to allow operations when the principal's tag matches the resource tag",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.14",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "LOW",
	execute: checkCloudFrontDistributionTags
} satisfies RuntimeTest;
