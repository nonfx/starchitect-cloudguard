import { APIGatewayClient, GetStagesCommand } from "@aws-sdk/client-api-gateway";
import { getAllRestApis } from "./get-all-rest-apis.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkApiGatewayLoggingCompliance(
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
				message: "No REST APIs found in the region"
			});
			return results;
		}

		for (const api of apis) {
			if (!api.id || !api.name) continue;

			try {
				// Get stages for each API
				const stagesResponse = await client.send(
					new GetStagesCommand({
						restApiId: api.id
					})
				);

				if (!stagesResponse.item || stagesResponse.item.length === 0) {
					results.checks.push({
						resourceName: api.name,
						status: ComplianceStatus.NOTAPPLICABLE,
						message: "No stages found for this API"
					});
					continue;
				}

				for (const stage of stagesResponse.item) {
					if (!stage.stageName) continue;

					// Check if logging is properly configured
					const accessLoggingEnabled =
						stage.accessLogSettings?.destinationArn && stage.accessLogSettings?.format;
					const methodSettings = stage.methodSettings || {};

					// Check if any method has proper logging level
					const hasValidLoggingLevel =
						Object.entries(methodSettings).length > 0 &&
						Object.values(methodSettings).some(
							settings => settings?.loggingLevel === "ERROR" || settings?.loggingLevel === "INFO"
						);

					const isCompliant = accessLoggingEnabled && hasValidLoggingLevel;

					results.checks.push({
						resourceName: `${api.name}/${stage.stageName}`,
						status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: isCompliant
							? undefined
							: "Stage does not have proper logging configuration (ERROR/INFO level and access logging)"
					});
				}
			} catch (error) {
				results.checks.push({
					resourceName: api.name,
					status: ComplianceStatus.ERROR,
					message: `Error checking API stages: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "API Gateway Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking API Gateway: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION || "ap-southeast-1";
	const results = await checkApiGatewayLoggingCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon API Gateway",
	shortServiceName: "apigateway",
	title: "API Gateway REST and WebSocket API execution logging should be enabled",
	description:
		"This control checks whether all stages of an Amazon API Gateway REST or WebSocket API have logging enabled. The control fails if the loggingLevel isn't ERROR or INFO for all stages of the API. Unless you provide custom parameter values to indicate that a specific log type should be enabled, Security Hub produces a passed finding if the logging level is either ERROR or INFO.API Gateway REST or WebSocket API stages should have relevant logs enabled. API Gateway REST and WebSocket API execution logging provides detailed records of requests made to API Gateway REST and WebSocket API stages. The stages include API integration backend responses, Lambda authorizer responses, and the requestId for AWS integration endpoints",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_APIGateway.1",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkApiGatewayLoggingCompliance
} satisfies RuntimeTest;
