// @ts-nocheck
import {
	APIGatewayClient,
	GetStagesCommand,
	GetRestApisCommand
} from "@aws-sdk/client-api-gateway";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkApiGatewayLogging from "./check-api-gateway-logging";

const mockApiGatewayClient = mockClient(APIGatewayClient);

const mockApi = {
	id: "abc123",
	name: "test-api"
};

const mockCompliantStage = {
	stageName: "prod",
	accessLogSettings: {
		destinationArn: "arn:aws:logs:us-east-1:123456789012:log-group:/aws/apigateway/test-api",
		format: "{ ... }"
	},
	methodSettings: {
		"*/*": {
			loggingLevel: "INFO"
		}
	}
};

const mockNonCompliantStage = {
	stageName: "dev",
	methodSettings: {
		"*/*": {
			loggingLevel: "OFF"
		}
	}
};

describe("checkApiGatewayLogging", () => {
	beforeEach(() => {
		mockApiGatewayClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when API stage has proper logging configuration", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({ items: [mockApi] });
			mockApiGatewayClient.on(GetStagesCommand).resolves({ item: [mockCompliantStage] });

			const result = await checkApiGatewayLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-api/prod");
		});

		it("should return NOTAPPLICABLE when no APIs exist", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({ items: [] });

			const result = await checkApiGatewayLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No REST APIs found in the region");
		});

		it("should return NOTAPPLICABLE when API has no stages", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({ items: [mockApi] });
			mockApiGatewayClient.on(GetStagesCommand).resolves({ item: [] });

			const result = await checkApiGatewayLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No stages found for this API");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when logging is not properly configured", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({ items: [mockApi] });
			mockApiGatewayClient.on(GetStagesCommand).resolves({ item: [mockNonCompliantStage] });

			const result = await checkApiGatewayLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("does not have proper logging configuration");
		});

		it("should handle mixed compliance scenarios", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({ items: [mockApi] });
			mockApiGatewayClient
				.on(GetStagesCommand)
				.resolves({ item: [mockCompliantStage, mockNonCompliantStage] });

			const result = await checkApiGatewayLogging.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when GetRestApis fails", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).rejects(new Error("API Error"));

			const result = await checkApiGatewayLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking API Gateway");
		});

		it("should return ERROR when GetStages fails", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({ items: [mockApi] });
			mockApiGatewayClient.on(GetStagesCommand).rejects(new Error("Stage Error"));

			const result = await checkApiGatewayLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking API stages");
		});
	});
});
