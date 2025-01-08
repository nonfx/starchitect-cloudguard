import { APIGatewayClient, GetStagesCommand } from "@aws-sdk/client-api-gateway";
import { getAllRestApis } from "./get-all-rest-apis.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkApiGatewayXrayTracingCompliance(
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
			results.checks = [
				{
					resourceName: "No REST APIs",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No API Gateway REST APIs found in the region"
				}
			];
			return results;
		}

		// Check each REST API's stages
		for (const api of apis) {
			if (!api.id || !api.name) {
				results.checks.push({
					resourceName: "Unknown API",
					status: ComplianceStatus.ERROR,
					message: "API found without ID or name"
				});
				continue;
			}

			try {
				const stagesResponse = await client.send(
					new GetStagesCommand({
						restApiId: api.id
					})
				);

				if (!stagesResponse.item || stagesResponse.item.length === 0) {
					results.checks.push({
						resourceName: `${api.name} (${api.id})`,
						status: ComplianceStatus.NOTAPPLICABLE,
						message: "No stages found for this API"
					});
					continue;
				}

				// Check X-Ray tracing for each stage
				for (const stage of stagesResponse.item) {
					if (!stage.stageName) {
						results.checks.push({
							resourceName: `${api.name || "Unknown API"}/Unknown Stage`,
							status: ComplianceStatus.ERROR,
							message: "Stage found without name"
						});
						continue;
					}

					const resourceName = `${api.name || "Unknown API"}/${stage.stageName}`;
					const resourceArn = `arn:aws:apigateway:${region}::/restapis/${api.id}/stages/${stage.stageName}`;

					results.checks.push({
						resourceName,
						resourceArn,
						status: stage.tracingEnabled === true ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message:
							stage.tracingEnabled === true
								? undefined
								: "X-Ray tracing is not enabled for this stage"
					});
				}
			} catch (error) {
				results.checks.push({
					resourceName: `${api.name} (${api.id})`,
					status: ComplianceStatus.ERROR,
					message: `Error checking stages: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "API Gateway Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking API Gateway: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION || "ap-southeast-1";
	const results = await checkApiGatewayXrayTracingCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon API Gateway",
	shortServiceName: "apigateway",
	title: "API Gateway REST API stages should have AWS X-Ray tracing enabled",
	description:
		"This control checks whether AWS X-Ray active tracing is enabled for your Amazon API Gateway REST API stages. X-Ray active tracing enables a more rapid response to performance changes in the underlying infrastructure. Changes in performance could result in a lack of availability of the API. X-Ray active tracing provides real-time metrics of user requests that flow through your API Gateway REST API operations and connected services.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_APIGateway.3",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkApiGatewayXrayTracingCompliance
} satisfies RuntimeTest;
