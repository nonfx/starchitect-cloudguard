import { APIGatewayClient, GetStagesCommand } from "@aws-sdk/client-api-gateway";
import { WAFRegionalClient, ListResourcesForWebACLCommand } from "@aws-sdk/client-waf-regional";
import {
	WAFV2Client,
	ListResourcesForWebACLCommand as ListWAFV2ResourcesCommand
} from "@aws-sdk/client-wafv2";
import { getAllRestApis } from "../../utils/aws/get-all-rest-apis.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkApiGatewayWafCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const apiClient = new APIGatewayClient({ region });
	const wafRegionalClient = new WAFRegionalClient({ region });
	const wafv2Client = new WAFV2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all REST APIs using pagination
		const apis = await getAllRestApis(apiClient);

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
				const stagesResponse = await apiClient.send(
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

				// Check each stage for WAF Web ACL association
				for (const stage of stagesResponse.item) {
					if (!stage.stageName) continue;

					const resourceName = `${api.name}/${stage.stageName}`;
					const resourceArn = `arn:aws:apigateway:${region}::/restapis/${api.id}/stages/${stage.stageName}`;

					try {
						// If no WAF ACL is configured, fail immediately
						if (!stage.webAclArn) {
							results.checks.push({
								resourceName,
								resourceArn,
								status: ComplianceStatus.FAIL,
								message: "API Gateway stage is not associated with a WAF Web ACL (Regional or v2)"
							});
							continue;
						}

						let hasWafAssociation = false;
						let hasCheckedRegional = false;
						let hasCheckedV2 = false;

						// Determine if this is a WAFv2 or WAF Regional ACL based on the ARN
						const isWafv2 = stage.webAclArn.includes(":wafv2:");

						if (isWafv2) {
							try {
								const wafv2Response = await wafv2Client.send(
									new ListWAFV2ResourcesCommand({
										WebACLArn: stage.webAclArn,
										ResourceType: "API_GATEWAY"
									})
								);
								hasCheckedV2 = true;
								if (wafv2Response.ResourceArns && wafv2Response.ResourceArns.length > 0) {
									hasWafAssociation = true;
								}
							} catch (error) {
								if (
									error instanceof Error &&
									!error.message.includes("AccessDenied") &&
									!error.message.includes("UnrecognizedClient")
								) {
									throw error;
								}
							}
						} else {
							try {
								const wafRegionalResponse = await wafRegionalClient.send(
									new ListResourcesForWebACLCommand({
										WebACLId: stage.webAclArn
									})
								);
								hasCheckedRegional = true;
								if (
									wafRegionalResponse.ResourceArns &&
									wafRegionalResponse.ResourceArns.length > 0
								) {
									hasWafAssociation = true;
								}
							} catch (error) {
								if (
									error instanceof Error &&
									!error.message.includes("AccessDenied") &&
									!error.message.includes("UnrecognizedClient")
								) {
									throw error;
								}
							}
						}

						// Determine final status - fail if we checked WAF types but found no association
						if (hasWafAssociation) {
							results.checks.push({
								resourceName,
								resourceArn,
								status: ComplianceStatus.PASS
							});
						} else {
							results.checks.push({
								resourceName,
								resourceArn,
								status: ComplianceStatus.FAIL,
								message: "API Gateway stage is not associated with a WAF Web ACL (Regional or v2)"
							});
						}
					} catch (error) {
						results.checks.push({
							resourceName,
							resourceArn,
							status: ComplianceStatus.ERROR,
							message: `Error checking WAF association: ${error instanceof Error ? error.message : String(error)}`
						});
					}
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
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION || "ap-southeast-1";
	const results = await checkApiGatewayWafCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon API Gateway",
	shortServiceName: "apigateway",
	title: "API Gateway should be associated with a WAF Web ACL",
	description:
		"This control checks whether an API Gateway stage uses an AWS WAF web access control list (ACL). This control fails if an AWS WAF web ACL is not attached to a REST API Gateway stage. AWS WAF is a web application firewall that helps protect web applications and APIs from attacks. It enables you to configure an ACL, which is a set of rules that allow, block, or count web requests based on customizable web security rules and conditions that you define. Ensure that your API Gateway stage is associated with an AWS WAF web ACL to help protect it from malicious attacks.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_APIGateway.4",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkApiGatewayWafCompliance
} satisfies RuntimeTest;
