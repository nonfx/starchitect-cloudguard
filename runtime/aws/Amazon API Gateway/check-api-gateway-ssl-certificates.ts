import { APIGatewayClient, GetStagesCommand } from "@aws-sdk/client-api-gateway";
import { getAllRestApis } from "./get-all-rest-apis.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkApiGatewaySslCertificates(
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
			if (!api.id || !api.name) continue;

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
						message: "No stages found for this REST API"
					});
					continue;
				}

				// Check each stage for SSL certificate configuration
				for (const stage of stagesResponse.item) {
					const resourceName = `${api.name}/${stage.stageName} (${api.id})`;

					results.checks.push({
						resourceName,
						status: stage.clientCertificateId ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: stage.clientCertificateId
							? undefined
							: "Stage does not have an SSL certificate configured for backend authentication"
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
	const region = process.env.AWS_REGION;
	const results = await checkApiGatewaySslCertificates(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon API Gateway",
	shortServiceName: "apigateway",
	title:
		"API Gateway REST API stages should be configured to use SSL certificates for backend authentication",
	description:
		"This control checks whether Amazon API Gateway REST API stages have SSL certificates configured. Backend systems use these certificates to authenticate that incoming requests are from API Gateway.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_APIGateway.2",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkApiGatewaySslCertificates
} satisfies RuntimeTest;
