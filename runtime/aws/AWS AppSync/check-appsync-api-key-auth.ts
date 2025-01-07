import { AppSyncClient, ListGraphqlApisCommand } from "@aws-sdk/client-appsync";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkAppSyncApiKeyAuth(region: string = "us-east-1"): Promise<ComplianceReport> {
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
							resourceName: "No AppSync APIs",
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
						message: "API found without name or ARN"
					});
					continue;
				}

				const isApiKeyAuth = api.authenticationType === "API_KEY";

				results.checks.push({
					resourceName: api.name,
					resourceArn: api.arn,
					status: isApiKeyAuth ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
					message: isApiKeyAuth ? "AppSync GraphQL API is using API key authentication" : undefined
				});
			}

			nextToken = response.nextToken;
		} while (nextToken);
	} catch (error) {
		results.checks = [
			{
				resourceName: "AppSync Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking AppSync APIs: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkAppSyncApiKeyAuth(region);
	printSummary(generateSummary(results));
}

export default {
	title: "AWS AppSync GraphQL APIs should not be authenticated with API keys",
	description:
		"This control checks whether your application uses an API key to interact with an AWS AppSync GraphQL API. The control fails if an AWS AppSync GraphQL API is authenticated with an API key.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_AppSync.5",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkAppSyncApiKeyAuth,
	serviceName: "AWS AppSync",
	shortServiceName: "appsync"
} satisfies RuntimeTest;
