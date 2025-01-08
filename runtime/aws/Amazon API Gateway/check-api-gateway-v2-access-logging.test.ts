// @ts-nocheck
import { ApiGatewayV2Client, GetApisCommand, GetStagesCommand } from "@aws-sdk/client-apigatewayv2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkApiGatewayV2AccessLogging from "./check-api-gateway-v2-access-logging";

const mockApiGatewayV2Client = mockClient(ApiGatewayV2Client);

const mockApi = {
	ApiId: "test-api-1",
	Name: "TestAPI",
	ApiEndpoint: "https://test-api.execute-api.us-east-1.amazonaws.com"
};

const mockStageWithLogging = {
	StageName: "prod",
	AccessLogSettings: {
		DestinationArn: "arn:aws:logs:us-east-1:123456789012:log-group:/aws/apigateway/test-api",
		Format: "$context.requestId $context.identity.sourceIp $context.identity.caller"
	}
};

const mockStageWithoutLogging = {
	StageName: "dev",
	AccessLogSettings: null
};

describe("checkApiGatewayV2AccessLogging", () => {
	beforeEach(() => {
		mockApiGatewayV2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when access logging is configured", async () => {
			mockApiGatewayV2Client.on(GetApisCommand).resolves({ Items: [mockApi] });
			mockApiGatewayV2Client.on(GetStagesCommand).resolves({ Items: [mockStageWithLogging] });

			const result = await checkApiGatewayV2AccessLogging("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("TestAPI/prod");
		});

		it("should return NOTAPPLICABLE when no APIs exist", async () => {
			mockApiGatewayV2Client.on(GetApisCommand).resolves({ Items: [] });

			const result = await checkApiGatewayV2AccessLogging("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No API Gateway V2 APIs found in the region");
		});

		it("should return NOTAPPLICABLE when API has no stages", async () => {
			mockApiGatewayV2Client.on(GetApisCommand).resolves({ Items: [mockApi] });
			mockApiGatewayV2Client.on(GetStagesCommand).resolves({ Items: [] });

			const result = await checkApiGatewayV2AccessLogging("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No stages found for this API");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when access logging is not configured", async () => {
			mockApiGatewayV2Client.on(GetApisCommand).resolves({ Items: [mockApi] });
			mockApiGatewayV2Client.on(GetStagesCommand).resolves({ Items: [mockStageWithoutLogging] });

			const result = await checkApiGatewayV2AccessLogging("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Stage does not have access logging configured");
		});

		it("should handle mixed compliance states", async () => {
			mockApiGatewayV2Client.on(GetApisCommand).resolves({ Items: [mockApi] });
			mockApiGatewayV2Client
				.on(GetStagesCommand)
				.resolves({ Items: [mockStageWithLogging, mockStageWithoutLogging] });

			const result = await checkApiGatewayV2AccessLogging("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when GetApis fails", async () => {
			mockApiGatewayV2Client.on(GetApisCommand).rejects(new Error("Failed to get APIs"));

			const result = await checkApiGatewayV2AccessLogging("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking API Gateway V2");
		});

		it("should return ERROR when GetStages fails", async () => {
			mockApiGatewayV2Client.on(GetApisCommand).resolves({ Items: [mockApi] });
			mockApiGatewayV2Client.on(GetStagesCommand).rejects(new Error("Failed to get stages"));

			const result = await checkApiGatewayV2AccessLogging("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking stages");
		});
	});
});
