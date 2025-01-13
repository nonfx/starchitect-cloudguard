import { AppSyncClient, ListGraphqlApisCommand } from "@aws-sdk/client-appsync";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkAppSyncGraphqlApiTagged(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new AppSyncClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let nextToken: string | undefined;
		let apisFound = false;

		do {
			const command = new ListGraphqlApisCommand({
				nextToken
			});

			const response = await client.send(command);

			if (!response.graphqlApis || response.graphqlApis.length === 0) {
				if (!apisFound) {
					results.checks = [
						{
							resourceName: "No GraphQL APIs",
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "No AppSync GraphQL APIs found in the region"
						}
					];
					return results;
				}
				break;
			}

			apisFound = true;

			for (const api of response.graphqlApis) {
				if (!api.name || !api.arn) {
					results.checks.push({
						resourceName: "Unknown API",
						status: ComplianceStatus.ERROR,
						message: "GraphQL API found without name or ARN"
					});
					continue;
				}

				// Filter out system tags (starting with 'aws:')
				const userTags = api.tags
					? Object.entries(api.tags).filter(([key]) => !key.startsWith("aws:"))
					: [];

				results.checks.push({
					resourceName: api.name,
					resourceArn: api.arn,
					status: userTags.length > 0 ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: userTags.length === 0 ? "GraphQL API has no user-defined tags" : undefined
				});
			}

			nextToken = response.nextToken;
		} while (nextToken);
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking AppSync GraphQL APIs: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkAppSyncGraphqlApiTagged(region);
	printSummary(generateSummary(results));
}

export default {
	title: "AWS AppSync GraphQL APIs should be tagged",
	description:
		"This control checks whether an AWS AppSync GraphQL API has tags with specific keys defined in the parameter requiredTagKeys. The control fails if the GraphQL API doesn't have any tag keys or if it doesn't have all the keys specified in the parameter requiredTagKeys. System tags, which begin with aws:, are ignored.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_AppSync.4",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkAppSyncGraphqlApiTagged,
	serviceName: "AWS AppSync",
	shortServiceName: "appsync"
} satisfies RuntimeTest;
