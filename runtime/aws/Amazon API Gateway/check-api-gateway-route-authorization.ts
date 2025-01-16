import { ApiGatewayV2Client, GetRoutesCommand } from "@aws-sdk/client-apigatewayv2";
import { getAllHttpApis } from "../../utils/aws/get-all-http-apis.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

const VALID_AUTH_TYPES = ["AWS_IAM", "CUSTOM", "JWT"];

async function checkApiGatewayRouteAuthorization(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new ApiGatewayV2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all HTTP/WebSocket APIs using pagination
		const apis = await getAllHttpApis(client);

		if (apis.length === 0) {
			results.checks = [
				{
					resourceName: "No API Gateway APIs",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No API Gateway HTTP/WebSocket APIs found in the region"
				}
			];
			return results;
		}

		// Check routes for each API
		for (const api of apis) {
			if (!api.ApiId) continue;

			try {
				const routesResponse = await client.send(
					new GetRoutesCommand({
						ApiId: api.ApiId
					})
				);

				if (!routesResponse.Items || routesResponse.Items.length === 0) {
					results.checks.push({
						resourceName: api.Name || "Unknown API",
						resourceArn: `arn:aws:apigateway:${region}::/apis/${api.ApiId}`,
						status: ComplianceStatus.NOTAPPLICABLE,
						message: "No routes found for this API"
					});
					continue;
				}

				// Check each route's authorization
				for (const route of routesResponse.Items) {
					const hasValidAuth =
						route.AuthorizationType && VALID_AUTH_TYPES.includes(route.AuthorizationType);

					results.checks.push({
						resourceName: `${api.Name || "Unknown API"} - ${route.RouteKey || "Unknown Route"}`,
						resourceArn: `arn:aws:apigateway:${region}::/apis/${api.ApiId}/routes/${route.RouteId}`,
						status: hasValidAuth ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: hasValidAuth ? undefined : "Route does not specify a valid authorization type"
					});
				}
			} catch (error) {
				results.checks.push({
					resourceName: api.Name || "Unknown API",
					resourceArn: `arn:aws:apigateway:${region}::/apis/${api.ApiId}`,
					status: ComplianceStatus.ERROR,
					message: `Error checking routes: ${error instanceof Error ? error.message : String(error)}`
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
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkApiGatewayRouteAuthorization(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon API Gateway",
	shortServiceName: "apigateway",
	title: "API Gateway routes should specify an authorization type",
	description:
		"This control checks if Amazon API Gateway routes have an authorization type. The control fails if the API Gateway route doesn't have any authorization type.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_APIGateway.8",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkApiGatewayRouteAuthorization
} satisfies RuntimeTest;
