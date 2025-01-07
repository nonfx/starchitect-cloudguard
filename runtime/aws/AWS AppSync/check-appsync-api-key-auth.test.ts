// @ts-nocheck
import { AppSyncClient, ListGraphqlApisCommand } from "@aws-sdk/client-appsync";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkAppSyncApiKeyAuth from "./check-appsync-api-key-auth";

const mockAppSyncClient = mockClient(AppSyncClient);

const mockApiWithApiKey = {
	name: "api-with-key",
	arn: "arn:aws:appsync:us-east-1:123456789012:apis/api-with-key",
	authenticationType: "API_KEY"
};

const mockApiWithIAM = {
	name: "api-with-iam",
	arn: "arn:aws:appsync:us-east-1:123456789012:apis/api-with-iam",
	authenticationType: "AWS_IAM"
};

describe("checkAppSyncApiKeyAuth", () => {
	beforeEach(() => {
		mockAppSyncClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for APIs not using API key authentication", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({
				graphqlApis: [mockApiWithIAM]
			});

			const result = await checkAppSyncApiKeyAuth.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("api-with-iam");
			expect(result.checks[0].resourceArn).toBe(mockApiWithIAM.arn);
		});

		it("should return NOTAPPLICABLE when no APIs exist", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({
				graphqlApis: []
			});

			const result = await checkAppSyncApiKeyAuth.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No AppSync GraphQL APIs found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for APIs using API key authentication", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({
				graphqlApis: [mockApiWithApiKey]
			});

			const result = await checkAppSyncApiKeyAuth.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("AppSync GraphQL API is using API key authentication");
		});

		it("should handle mixed authentication types", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({
				graphqlApis: [mockApiWithApiKey, mockApiWithIAM]
			});

			const result = await checkAppSyncApiKeyAuth.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).rejects(new Error("API Error"));

			const result = await checkAppSyncApiKeyAuth.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking AppSync APIs: API Error");
		});

		it("should handle APIs without name or ARN", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({
				graphqlApis: [{ authenticationType: "API_KEY" }]
			});

			const result = await checkAppSyncApiKeyAuth.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("API found without name or ARN");
		});
	});

	describe("Pagination", () => {
		it("should handle paginated results", async () => {
			mockAppSyncClient
				.on(ListGraphqlApisCommand)
				.resolvesOnce({
					graphqlApis: [mockApiWithApiKey],
					nextToken: "token1"
				})
				.resolvesOnce({
					graphqlApis: [mockApiWithIAM]
				});

			const result = await checkAppSyncApiKeyAuth.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});
	});
});
