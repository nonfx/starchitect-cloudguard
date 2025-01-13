// @ts-nocheck
import { AppSyncClient, ListGraphqlApisCommand } from "@aws-sdk/client-appsync";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkAppSyncGraphqlApiTagged from "./check-appsync-graphql-api-tagged";

const mockAppSyncClient = mockClient(AppSyncClient);

const mockTaggedApi = {
	name: "tagged-api",
	arn: "arn:aws:appsync:us-east-1:123456789012:apis/tagged-api",
	tags: {
		environment: "production",
		owner: "team-a"
	}
};

const mockUntaggedApi = {
	name: "untagged-api",
	arn: "arn:aws:appsync:us-east-1:123456789012:apis/untagged-api",
	tags: {}
};

const mockSystemTaggedApi = {
	name: "system-tagged-api",
	arn: "arn:aws:appsync:us-east-1:123456789012:apis/system-tagged-api",
	tags: {
		"aws:created": "system",
		environment: "staging"
	}
};

describe("checkAppSyncGraphqlApiTagged", () => {
	beforeEach(() => {
		mockAppSyncClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for APIs with user-defined tags", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({
				graphqlApis: [mockTaggedApi]
			});

			const result = await checkAppSyncGraphqlApiTagged.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("tagged-api");
			expect(result.checks[0].resourceArn).toBe(mockTaggedApi.arn);
		});

		it("should return PASS for APIs with both system and user tags", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({
				graphqlApis: [mockSystemTaggedApi]
			});

			const result = await checkAppSyncGraphqlApiTagged.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});

		it("should return NOTAPPLICABLE when no APIs exist", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({
				graphqlApis: []
			});

			const result = await checkAppSyncGraphqlApiTagged.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No AppSync GraphQL APIs found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for APIs without user-defined tags", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({
				graphqlApis: [mockUntaggedApi]
			});

			const result = await checkAppSyncGraphqlApiTagged.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("GraphQL API has no user-defined tags");
		});

		it("should handle multiple APIs with mixed compliance", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({
				graphqlApis: [mockTaggedApi, mockUntaggedApi]
			});

			const result = await checkAppSyncGraphqlApiTagged.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).rejects(new Error("API Error"));

			const result = await checkAppSyncGraphqlApiTagged.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking AppSync GraphQL APIs");
		});

		it("should handle APIs without name or ARN", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({
				graphqlApis: [{ tags: { environment: "prod" } }]
			});

			const result = await checkAppSyncGraphqlApiTagged.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("GraphQL API found without name or ARN");
		});
	});

	describe("Pagination", () => {
		it("should handle paginated results", async () => {
			mockAppSyncClient
				.on(ListGraphqlApisCommand)
				.resolvesOnce({
					graphqlApis: [mockTaggedApi],
					nextToken: "token1"
				})
				.resolvesOnce({
					graphqlApis: [mockUntaggedApi]
				});

			const result = await checkAppSyncGraphqlApiTagged.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});
});
