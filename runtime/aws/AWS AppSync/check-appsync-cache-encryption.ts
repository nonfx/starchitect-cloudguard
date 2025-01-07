import { AppSyncClient, ListGraphqlApisCommand, GetApiCacheCommand } from "@aws-sdk/client-appsync";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkAppSyncApiCacheEncryption(
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
			// Get all GraphQL APIs
			const listApisResponse = await client.send(
				new ListGraphqlApisCommand({
					nextToken
				})
			);

			if (!listApisResponse.graphqlApis || listApisResponse.graphqlApis.length === 0) {
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

			// Check each API for cache configuration
			for (const api of listApisResponse.graphqlApis) {
				if (!api.apiId || !api.name) {
					results.checks.push({
						resourceName: "Unknown API",
						status: ComplianceStatus.ERROR,
						message: "API found without ID or name"
					});
					continue;
				}

				try {
					const cacheResponse = await client.send(
						new GetApiCacheCommand({
							apiId: api.apiId
						})
					);

					if (!cacheResponse.apiCache) {
						results.checks.push({
							resourceName: api.name,
							resourceArn: api.arn,
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "No cache configuration found for this API"
						});
						continue;
					}

					const isEncrypted = cacheResponse.apiCache.atRestEncryptionEnabled === true;

					results.checks.push({
						resourceName: api.name,
						resourceArn: api.arn,
						status: isEncrypted ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: isEncrypted ? undefined : "AppSync API cache is not encrypted at rest"
					});
				} catch (error) {
					results.checks.push({
						resourceName: api.name,
						resourceArn: api.arn,
						status: ComplianceStatus.ERROR,
						message: `Error checking API cache: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			}

			nextToken = listApisResponse.nextToken;
		} while (nextToken);
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
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
	const results = await checkAppSyncApiCacheEncryption(region);
	printSummary(generateSummary(results));
}

export default {
	title: "AWS AppSync API caches should be encrypted at rest",
	description:
		"AWS AppSync API caches must implement encryption at rest to protect data confidentiality and prevent unauthorized access.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_AppSync.1",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkAppSyncApiCacheEncryption,
	serviceName: "AWS AppSync",
	shortServiceName: "appsync"
} satisfies RuntimeTest;
