// @ts-nocheck
import {
	APIGatewayClient,
	GetStagesCommand,
	GetRestApisCommand
} from "@aws-sdk/client-api-gateway";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkApiGatewayCacheEncryption from "./check-api-gateway-cache-encryption";

const mockApiGatewayClient = mockClient(APIGatewayClient);

const mockApi = {
	id: "abc123",
	name: "test-api"
};

const mockStageWithEncryptedCache = {
	stageName: "prod",
	deploymentId: "dep-123",
	cacheClusterEnabled: true,
	cacheClusterSize: "0.5",
	methodSettings: {
		"*/*": {
			cacheDataEncrypted: true
		}
	}
};

const mockStageWithUnencryptedCache = {
	stageName: "dev",
	deploymentId: "dep-456",
	cacheClusterEnabled: true,
	cacheClusterSize: "0.5",
	methodSettings: {
		"*/*": {
			cacheDataEncrypted: false
		}
	}
};

const mockStageWithoutCache = {
	stageName: "test",
	deploymentId: "dep-789",
	cacheClusterEnabled: false
};

describe("checkApiGatewayCacheEncryption", () => {
	beforeEach(() => {
		mockApiGatewayClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when cache encryption is enabled", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({ items: [mockApi] });
			mockApiGatewayClient.on(GetStagesCommand).resolves({ item: [mockStageWithEncryptedCache] });

			const result = await checkApiGatewayCacheEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-api/prod");
		});

		it("should return PASS when caching is not enabled", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({ items: [mockApi] });
			mockApiGatewayClient.on(GetStagesCommand).resolves({ item: [mockStageWithoutCache] });

			const result = await checkApiGatewayCacheEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toBe("Caching is not enabled for this stage");
		});

		it("should return NOTAPPLICABLE when no APIs exist", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({ items: [] });

			const result = await checkApiGatewayCacheEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No REST APIs found");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when cache encryption is disabled", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({ items: [mockApi] });
			mockApiGatewayClient.on(GetStagesCommand).resolves({ item: [mockStageWithUnencryptedCache] });

			const result = await checkApiGatewayCacheEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Cache is enabled but encryption is not configured for one or more methods"
			);
		});

		it("should handle mixed encryption configurations", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({ items: [mockApi] });
			mockApiGatewayClient.on(GetStagesCommand).resolves({
				item: [mockStageWithEncryptedCache, mockStageWithUnencryptedCache]
			});

			const result = await checkApiGatewayCacheEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when GetRestApis fails", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).rejects(new Error("API Error"));

			const result = await checkApiGatewayCacheEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking API Gateway");
		});

		it("should return ERROR when GetStages fails", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({ items: [mockApi] });
			mockApiGatewayClient.on(GetStagesCommand).rejects(new Error("Stage Error"));

			const result = await checkApiGatewayCacheEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking API stages");
		});

		it("should return NOTAPPLICABLE when API has no stages", async () => {
			mockApiGatewayClient.on(GetRestApisCommand).resolves({ items: [mockApi] });
			mockApiGatewayClient.on(GetStagesCommand).resolves({ item: [] });

			const result = await checkApiGatewayCacheEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No stages found for this API");
		});
	});
});
