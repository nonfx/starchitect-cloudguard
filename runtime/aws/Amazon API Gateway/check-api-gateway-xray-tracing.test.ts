// @ts-nocheck
import {
	APIGatewayClient,
	GetStagesCommand,
	GetRestApisCommand
} from "@aws-sdk/client-api-gateway";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkApiGatewayXrayTracing from "./check-api-gateway-xray-tracing";

const mockApiGatewayClient = mockClient(APIGatewayClient);

const mockApi = {
	id: "api123",
	name: "test-api"
};

const mockStageWithTracing = {
	stageName: "prod",
	tracingEnabled: true
};

const mockStageWithoutTracing = {
	stageName: "dev",
	tracingEnabled: false
};

describe("checkApiGatewayXrayTracing", () => {
	beforeEach(() => {
		mockApiGatewayClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when X-Ray tracing is enabled for all stages", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({ items: [mockApi] });
			mockApiGatewayClient.on(GetStagesCommand).resolves({ item: [mockStageWithTracing] });

			const result = await checkApiGatewayXrayTracing.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-api/prod");
		});

		it("should return NOTAPPLICABLE when no APIs exist", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({ items: [] });

			const result = await checkApiGatewayXrayTracing.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No API Gateway REST APIs found in the region");
		});

		it("should return NOTAPPLICABLE when API has no stages", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({ items: [mockApi] });
			mockApiGatewayClient.on(GetStagesCommand).resolves({ item: [] });

			const result = await checkApiGatewayXrayTracing.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No stages found for this API");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when X-Ray tracing is disabled", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({ items: [mockApi] });
			mockApiGatewayClient.on(GetStagesCommand).resolves({ item: [mockStageWithoutTracing] });

			const result = await checkApiGatewayXrayTracing.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("X-Ray tracing is not enabled for this stage");
		});

		it("should handle mixed tracing configurations", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({ items: [mockApi] });
			mockApiGatewayClient
				.on(GetStagesCommand)
				.resolves({ item: [mockStageWithTracing, mockStageWithoutTracing] });

			const result = await checkApiGatewayXrayTracing.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when GetRestApis fails", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).rejects(new Error("API Error"));

			const result = await checkApiGatewayXrayTracing.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking API Gateway");
		});

		it("should return ERROR when GetStages fails", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({ items: [mockApi] });
			mockApiGatewayClient.on(GetStagesCommand).rejects(new Error("Stage Error"));

			const result = await checkApiGatewayXrayTracing.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking stages");
		});

		it("should handle APIs without ID or name", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({ items: [{}] });

			const result = await checkApiGatewayXrayTracing.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("API found without ID or name");
		});
	});
});
