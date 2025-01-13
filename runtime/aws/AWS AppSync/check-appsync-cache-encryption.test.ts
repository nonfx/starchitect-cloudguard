// @ts-nocheck
import { AppSyncClient, ListGraphqlApisCommand, GetApiCacheCommand } from "@aws-sdk/client-appsync";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkAppSyncCacheEncryption from "./check-appsync-cache-encryption";

const mockAppSyncClient = mockClient(AppSyncClient);

const mockApi = {
	name: "test-api",
	apiId: "test-api-id",
	arn: "arn:aws:appsync:us-east-1:123456789012:apis/test-api-id"
};

describe("checkAppSyncCacheEncryption", () => {
	beforeEach(() => {
		mockAppSyncClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when API cache is encrypted", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({ graphqlApis: [mockApi] });
			mockAppSyncClient.on(GetApiCacheCommand).resolves({
				apiCache: {
					atRestEncryptionEnabled: true
				}
			});

			const result = await checkAppSyncCacheEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-api");
			expect(result.checks[0].resourceArn).toBe(mockApi.arn);
		});

		it("should return NOTAPPLICABLE when no cache is configured", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({ graphqlApis: [mockApi] });
			mockAppSyncClient.on(GetApiCacheCommand).resolves({ apiCache: null });

			const result = await checkAppSyncCacheEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No cache configuration found for this API");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when API cache is not encrypted", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({ graphqlApis: [mockApi] });
			mockAppSyncClient.on(GetApiCacheCommand).resolves({
				apiCache: {
					atRestEncryptionEnabled: false
				}
			});

			const result = await checkAppSyncCacheEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("AppSync API cache is not encrypted at rest");
		});

		it("should handle multiple APIs with mixed encryption settings", async () => {
			const secondApi = { ...mockApi, name: "test-api-2", apiId: "test-api-id-2" };
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({ graphqlApis: [mockApi, secondApi] });
			mockAppSyncClient
				.on(GetApiCacheCommand)
				.resolves({ apiCache: { atRestEncryptionEnabled: true } })
				.on(GetApiCacheCommand, { apiId: "test-api-id-2" })
				.resolves({ apiCache: { atRestEncryptionEnabled: false } });

			const result = await checkAppSyncCacheEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no APIs exist", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({ graphqlApis: [] });

			const result = await checkAppSyncCacheEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No AppSync GraphQL APIs found in the region");
		});

		it("should handle ListGraphqlApis API errors", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).rejects(new Error("API Error"));

			const result = await checkAppSyncCacheEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking AppSync APIs");
		});

		it("should handle GetApiCache API errors", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({ graphqlApis: [mockApi] });
			mockAppSyncClient.on(GetApiCacheCommand).rejects(new Error("Cache API Error"));

			const result = await checkAppSyncCacheEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking API cache");
		});

		it("should handle pagination", async () => {
			mockAppSyncClient
				.on(ListGraphqlApisCommand)
				.resolvesOnce({
					graphqlApis: [mockApi],
					nextToken: "token1"
				})
				.resolvesOnce({
					graphqlApis: [{ ...mockApi, name: "test-api-2", apiId: "test-api-id-2" }]
				});
			mockAppSyncClient
				.on(GetApiCacheCommand)
				.resolves({ apiCache: { atRestEncryptionEnabled: true } });

			const result = await checkAppSyncCacheEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
		});
	});
});
