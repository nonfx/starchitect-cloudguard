// @ts-nocheck
import {
	APIGatewayClient,
	GetRestApisCommand,
	GetStagesCommand
} from "@aws-sdk/client-api-gateway";
import { WAFRegionalClient, ListResourcesForWebACLCommand } from "@aws-sdk/client-waf-regional";
import {
	WAFV2Client,
	ListResourcesForWebACLCommand as ListWAFV2ResourcesCommand
} from "@aws-sdk/client-wafv2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkApiGatewayWaf from "./check-api-gateway-waf.js";

const mockApiGatewayClient = mockClient(APIGatewayClient);
const mockWafRegionalClient = mockClient(WAFRegionalClient);
const mockWafv2Client = mockClient(WAFV2Client);

describe("checkApiGatewayWaf", () => {
	beforeEach(() => {
		mockApiGatewayClient.reset();
		mockWafRegionalClient.reset();
		mockWafv2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when API Gateway stage has WAF Regional Web ACL", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({
				items: [
					{
						id: "abc123",
						name: "test-api"
					}
				]
			});

			mockApiGatewayClient.on(GetStagesCommand).resolves({
				item: [
					{
						stageName: "prod",
						webAclArn: "arn:aws:wafregional:us-east-1:123456789012:webacl/test-acl"
					}
				]
			});

			mockWafRegionalClient.on(ListResourcesForWebACLCommand).resolves({
				ResourceArns: ["arn:aws:apigateway:us-east-1::/restapis/abc123/stages/prod"]
			});

			const result = await checkApiGatewayWaf.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-api/prod");
		});

		it("should return PASS when API Gateway stage has WAFv2 Web ACL", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({
				items: [
					{
						id: "abc123",
						name: "test-api"
					}
				]
			});

			mockApiGatewayClient.on(GetStagesCommand).resolves({
				item: [
					{
						stageName: "prod",
						webAclArn: "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test-acl"
					}
				]
			});

			mockWafRegionalClient.on(ListResourcesForWebACLCommand).rejects({
				name: "AccessDeniedException",
				message: "Access Denied"
			});

			mockWafv2Client.on(ListWAFV2ResourcesCommand).resolves({
				ResourceArns: ["arn:aws:apigateway:us-east-1::/restapis/abc123/stages/prod"]
			});

			const result = await checkApiGatewayWaf.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-api/prod");
		});

		it("should return NOTAPPLICABLE when no REST APIs exist", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({
				items: []
			});

			const result = await checkApiGatewayWaf.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No API Gateway REST APIs found in the region");
		});

		it("should return NOTAPPLICABLE when API has no stages", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({
				items: [
					{
						id: "abc123",
						name: "test-api"
					}
				]
			});

			mockApiGatewayClient.on(GetStagesCommand).resolves({
				item: []
			});

			const result = await checkApiGatewayWaf.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No stages found for this API");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when API Gateway stage has no WAF Web ACL", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({
				items: [
					{
						id: "abc123",
						name: "test-api"
					}
				]
			});

			mockApiGatewayClient.on(GetStagesCommand).resolves({
				item: [
					{
						stageName: "prod"
					}
				]
			});

			const result = await checkApiGatewayWaf.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"API Gateway stage is not associated with a WAF Web ACL (Regional or v2)"
			);
		});

		it("should handle mixed compliance results", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({
				items: [
					{
						id: "abc123",
						name: "test-api"
					}
				]
			});

			mockApiGatewayClient.on(GetStagesCommand).resolves({
				item: [
					{ stageName: "prod", webAclArn: "arn:aws:wafregional::/webacl/prod-acl" },
					{ stageName: "dev" }
				]
			});

			mockWafRegionalClient.on(ListResourcesForWebACLCommand).resolves({
				ResourceArns: ["arn:aws:apigateway::/restapis/abc123/stages/prod"]
			});

			const result = await checkApiGatewayWaf.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API Gateway call fails", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).rejects(new Error("API Gateway Error"));

			const result = await checkApiGatewayWaf.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking API Gateway: API Gateway Error");
		});

		it("should return ERROR when WAF calls fail with non-access errors", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({
				items: [
					{
						id: "abc123",
						name: "test-api"
					}
				]
			});

			mockApiGatewayClient.on(GetStagesCommand).resolves({
				item: [
					{
						stageName: "prod",
						webAclArn: "arn:aws:wafregional::/webacl/test"
					}
				]
			});

			mockWafRegionalClient.on(ListResourcesForWebACLCommand).rejects(new Error("WAF Error"));
			mockWafv2Client.on(ListWAFV2ResourcesCommand).rejects(new Error("WAFv2 Error"));

			const result = await checkApiGatewayWaf.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking WAF association");
		});
	});
});
