import {
	CloudTrailClient,
	GetTrailCommand,
	ListTagsCommand,
	ListTrailsCommand
} from "@aws-sdk/client-cloudtrail";
import { generateSummary, printSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkCloudTrailTagged(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new CloudTrailClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get list of all trails
		const listTrailsResponse = await client.send(new ListTrailsCommand({}));

		if (!listTrailsResponse.Trails || listTrailsResponse.Trails.length === 0) {
			results.checks = [
				{
					resourceName: "No CloudTrail Trails",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No CloudTrail trails found in the region"
				}
			];
			return results;
		}

		// Check each trail for tags
		for (const trail of listTrailsResponse.Trails) {
			if (!trail.TrailARN) {
				results.checks.push({
					resourceName: "Unknown Trail",
					status: ComplianceStatus.ERROR,
					message: "Trail found without ARN"
				});
				continue;
			}

			try {
				// Get trail details for the name
				const getTrailResponse = await client.send(new GetTrailCommand({ Name: trail.TrailARN }));

				if (!getTrailResponse.Trail) {
					results.checks.push({
						resourceName: trail.TrailARN,
						resourceArn: trail.TrailARN,
						status: ComplianceStatus.ERROR,
						message: "Could not retrieve trail details"
					});
					continue;
				}

				// Get tags using ListTagsCommand
				const listTagsResponse = await client.send(
					new ListTagsCommand({ ResourceIdList: [trail.TrailARN] })
				);

				// Check if trail has any non-system tags
				const resourceTag = listTagsResponse.ResourceTagList?.[0];
				const tags = resourceTag?.TagsList || [];
				const nonSystemTags = tags.filter((tag: { Key?: string }) => !tag.Key?.startsWith("aws:"));

				results.checks.push({
					resourceName: getTrailResponse.Trail.Name || trail.TrailARN,
					resourceArn: trail.TrailARN,
					status: nonSystemTags.length > 0 ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message:
						nonSystemTags.length > 0
							? undefined
							: "CloudTrail trail does not have any non-system tags"
				});
			} catch (error) {
				results.checks.push({
					resourceName: trail.TrailARN,
					resourceArn: trail.TrailARN,
					status: ComplianceStatus.ERROR,
					message: `Error checking trail tags: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "CloudTrail Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking CloudTrail trails: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkCloudTrailTagged(region);
	printSummary(generateSummary(results));
}

export default {
	title: "CloudTrail trails should be tagged",
	description:
		"This control checks whether an AWS CloudTrail trail has tags with the specific keys defined in the parameter requiredTagKeys. The control fails if the trail doesn't have any tag keys or if it doesn't have all the keys specified in the parameter requiredTagKeys. If the parameter requiredTagKeys isn't provided, the control only checks for the existence of a tag key and fails if the trail isn't tagged with any key. System tags, which are automatically applied and begin with aws:, are ignored.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_CloudTrail.9",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkCloudTrailTagged
} satisfies RuntimeTest;
