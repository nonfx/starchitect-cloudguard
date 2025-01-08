import { ApiGatewayV2Client, GetApisCommand, GetStagesCommand } from "@aws-sdk/client-apigatewayv2";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkApiGatewayV2AccessLogging(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new ApiGatewayV2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all API Gateway V2 APIs
		const apisResponse = await client.send(new GetApisCommand({}));

		if (!apisResponse.Items || apisResponse.Items.length === 0) {
			results.checks = [
				{
					resourceName: "No API Gateway V2 APIs",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No API Gateway V2 APIs found in the region"
				}
			];
			return results;
		}

		// Check each API's stages
		for (const api of apisResponse.Items) {
			if (!api.ApiId) continue;

			try {
				const stagesResponse = await client.send(
					new GetStagesCommand({
						ApiId: api.ApiId
					})
				);

				if (!stagesResponse.Items || stagesResponse.Items.length === 0) {
					results.checks.push({
						resourceName: api.Name || "Unknown API",
						resourceArn: api.ApiEndpoint,
						status: ComplianceStatus.NOTAPPLICABLE,
						message: "No stages found for this API"
					});
					continue;
				}

				// Check each stage for access logging
				for (const stage of stagesResponse.Items) {
					const stageName = stage.StageName || "Unknown Stage";
					const resourceName = `${api.Name || "Unknown API"}/${stageName}`;

					const hasAccessLogging =
						stage.AccessLogSettings?.DestinationArn && stage.AccessLogSettings?.Format;

					results.checks.push({
						resourceName,
						resourceArn: api.ApiEndpoint,
						status: hasAccessLogging ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: hasAccessLogging ? undefined : "Stage does not have access logging configured"
					});
				}
			} catch (error) {
				results.checks.push({
					resourceName: api.Name || "Unknown API",
					resourceArn: api.ApiEndpoint,
					status: ComplianceStatus.ERROR,
					message: `Error checking stages: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "API Gateway V2 Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking API Gateway V2: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkApiGatewayV2AccessLogging(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon API Gateway",
	shortServiceName: "apigateway",
	title: "Access logging should be configured for API Gateway V2 Stages",
	description:
		"This control checks if Amazon API Gateway V2 stages have access logging configured. This control fails if access log settings aren't defined.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_APIGateway.9",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkApiGatewayV2AccessLogging
} satisfies RuntimeTest;
