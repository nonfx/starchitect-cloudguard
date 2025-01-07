import {
	AppSyncClient,
	ListGraphqlApisCommand,
	GetGraphqlApiCommand
} from "@aws-sdk/client-appsync";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkAppSyncFieldLogging(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new AppSyncClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let nextToken: string | undefined;
		let apisFound = false;

		do {
			// Get list of all AppSync APIs
			const listCommand = new ListGraphqlApisCommand({
				nextToken
			});
			const response = await client.send(listCommand);

			if (!response.graphqlApis || response.graphqlApis.length === 0) {
				if (!apisFound) {
					results.checks = [
						{
							resourceName: "No AppSync APIs",
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "No AppSync APIs found in the region"
						}
					];
					return results;
				}
				break;
			}

			apisFound = true;

			// Check each API's logging configuration
			for (const api of response.graphqlApis) {
				if (!api.apiId || !api.name) {
					results.checks.push({
						resourceName: "Unknown API",
						status: ComplianceStatus.ERROR,
						message: "API found without ID or name"
					});
					continue;
				}

				try {
					const getApiCommand = new GetGraphqlApiCommand({
						apiId: api.apiId
					});
					const apiDetails = await client.send(getApiCommand);

					const logConfig = apiDetails.graphqlApi?.logConfig;
					const fieldLogLevel = logConfig?.fieldLogLevel;

					const isLoggingEnabled = fieldLogLevel && fieldLogLevel !== "NONE";

					results.checks.push({
						resourceName: api.name,
						resourceArn: api.arn,
						status: isLoggingEnabled ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: isLoggingEnabled
							? undefined
							: "Field-level logging is not enabled or set to NONE"
					});
				} catch (error) {
					results.checks.push({
						resourceName: api.name,
						resourceArn: api.arn,
						status: ComplianceStatus.ERROR,
						message: `Error checking API logging configuration: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			}

			nextToken = response.nextToken;
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
	const results = await checkAppSyncFieldLogging(region);
	printSummary(generateSummary(results));
}

export default {
	title: "AWS AppSync should have field-level logging enabled",
	description:
		"This control checks whether an AWS AppSync API has field-level logging turned on. The control fails if the field resolver log level is set to None. Security Hub produces a passed finding if the field resolver log level is either ERROR or ALL. Logging and metrics help identify, troubleshoot, and optimize GraphQL queries.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_AppSync.2",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkAppSyncFieldLogging,
	serviceName: "AWS AppSync",
	shortServiceName: "appsync"
} satisfies RuntimeTest;
