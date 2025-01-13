//@ts-nocheck
import {
	AppSyncClient,
	ListGraphqlApisCommand,
	GetGraphqlApiCommand
} from "@aws-sdk/client-appsync";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkAppSyncFieldLogging from "./check-appsync-field-logging";

const mockAppSyncClient = mockClient(AppSyncClient);

const mockApi1 = {
	apiId: "api1",
	name: "test-api-1",
	arn: "arn:aws:appsync:us-east-1:123456789012:apis/api1"
};

const mockApi2 = {
	apiId: "api2",
	name: "test-api-2",
	arn: "arn:aws:appsync:us-east-1:123456789012:apis/api2"
};

describe("checkAppSyncFieldLogging", () => {
	beforeEach(() => {
		mockAppSyncClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when field-level logging is enabled with ERROR level", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({ graphqlApis: [mockApi1] });
			mockAppSyncClient.on(GetGraphqlApiCommand).resolves({
				graphqlApi: {
					...mockApi1,
					logConfig: { fieldLogLevel: "ERROR" }
				}
			});

			const result = await checkAppSyncFieldLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-api-1");
		});

		it("should return PASS when field-level logging is set to ALL", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({ graphqlApis: [mockApi1] });
			mockAppSyncClient.on(GetGraphqlApiCommand).resolves({
				graphqlApi: {
					...mockApi1,
					logConfig: { fieldLogLevel: "ALL" }
				}
			});

			const result = await checkAppSyncFieldLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when field-level logging is set to NONE", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({ graphqlApis: [mockApi1] });
			mockAppSyncClient.on(GetGraphqlApiCommand).resolves({
				graphqlApi: {
					...mockApi1,
					logConfig: { fieldLogLevel: "NONE" }
				}
			});

			const result = await checkAppSyncFieldLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Field-level logging is not enabled or set to NONE");
		});

		it("should return FAIL when logging configuration is missing", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({ graphqlApis: [mockApi1] });
			mockAppSyncClient.on(GetGraphqlApiCommand).resolves({
				graphqlApi: {
					...mockApi1,
					logConfig: {}
				}
			});

			const result = await checkAppSyncFieldLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no APIs exist", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).resolves({ graphqlApis: [] });

			const result = await checkAppSyncFieldLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No AppSync APIs found in the region");
		});

		it("should handle API listing errors", async () => {
			mockAppSyncClient.on(ListGraphqlApisCommand).rejects(new Error("Failed to list APIs"));

			const result = await checkAppSyncFieldLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to list APIs");
		});

		it("should handle pagination", async () => {
			mockAppSyncClient
				.on(ListGraphqlApisCommand)
				.resolvesOnce({
					graphqlApis: [mockApi1],
					nextToken: "token1"
				})
				.resolvesOnce({
					graphqlApis: [mockApi2]
				});

			mockAppSyncClient.on(GetGraphqlApiCommand).resolves({
				graphqlApi: {
					logConfig: { fieldLogLevel: "ERROR" }
				}
			});

			const result = await checkAppSyncFieldLogging.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
		});
	});
});
