import { APIGatewayClient, GetStagesCommand } from "@aws-sdk/client-api-gateway";
import { getAllRestApis } from "../../utils/aws/get-all-rest-apis.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkApiGatewayCacheEncryption(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new APIGatewayClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all REST APIs using pagination
		const apis = await getAllRestApis(client);

		if (apis.length === 0) {
			results.checks.push({
				resourceName: "API Gateway",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No REST APIs found"
			});
			return results;
		}

		// Check each REST API
		for (const api of apis) {
			if (!api.id) continue;

			// Get stages for each REST API
			const stagesCommand = new GetStagesCommand({
				restApiId: api.id
			});

			try {
				const stagesResponse = await client.send(stagesCommand);

				if (!stagesResponse.item || stagesResponse.item.length === 0) {
					results.checks.push({
						resourceName: `API ${api.name || api.id}`,
						status: ComplianceStatus.NOTAPPLICABLE,
						message: "No stages found for this API"
					});
					continue;
				}

				// Check each stage
				for (const stage of stagesResponse.item) {
					const resourceName = `${api.name || api.id}/${stage.stageName}`;

					// Check if caching is enabled
					if (!stage.cacheClusterEnabled || !stage.cacheClusterSize) {
						results.checks.push({
							resourceName,
							status: ComplianceStatus.PASS,
							message: "Caching is not enabled for this stage"
						});
						continue;
					}

					// Check if cache encryption is enabled for all methods
					let allMethodsEncrypted = true;
					const methodSettings = stage.methodSettings || {};

					// If no method settings are configured, consider it as not encrypted
					if (Object.keys(methodSettings).length === 0) {
						allMethodsEncrypted = false;
					} else {
						// Check each method setting
						for (const [methodPath, settings] of Object.entries(methodSettings)) {
							if (!settings.cacheDataEncrypted) {
								allMethodsEncrypted = false;
								break;
							}
						}
					}

					results.checks.push({
						resourceName,
						resourceArn: stage.deploymentId,
						status: allMethodsEncrypted ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: allMethodsEncrypted
							? undefined
							: "Cache is enabled but encryption is not configured for one or more methods"
					});
				}
			} catch (error) {
				results.checks.push({
					resourceName: `API ${api.name || api.id}`,
					status: ComplianceStatus.ERROR,
					message: `Error checking API stages: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "API Gateway",
			status: ComplianceStatus.ERROR,
			message: `Error checking API Gateway: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkApiGatewayCacheEncryption(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon API Gateway",
	shortServiceName: "apigateway",
	title: "API Gateway REST API cache data should be encrypted at rest",
	description:
		"This control checks whether all methods in API Gateway REST API stages that have cache enabled are encrypted. The control fails if any method in an API Gateway REST API stage is configured to cache and the cache is not encrypted.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_APIGateway.5",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkApiGatewayCacheEncryption
} satisfies RuntimeTest;
