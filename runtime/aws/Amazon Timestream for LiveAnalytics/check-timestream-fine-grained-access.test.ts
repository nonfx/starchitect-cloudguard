// @ts-nocheck
import { TimestreamWriteClient, ListDatabasesCommand } from "@aws-sdk/client-timestream-write";
import { IAMClient, ListPoliciesCommand, GetPolicyVersionCommand } from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkTimestreamFineGrainedAccess from "./check-timestream-fine-grained-access";

const mockTimestreamClient = mockClient(TimestreamWriteClient);
const mockIAMClient = mockClient(IAMClient);

const mockDatabases = [{ DatabaseName: "test-db-1" }, { DatabaseName: "test-db-2" }];

const mockPolicies = [
	{
		PolicyName: "fine-grained-policy",
		Arn: "arn:aws:iam::123456789012:policy/fine-grained-policy",
		DefaultVersionId: "v1"
	},
	{
		PolicyName: "broad-access-policy",
		Arn: "arn:aws:iam::123456789012:policy/broad-access-policy",
		DefaultVersionId: "v1"
	}
];

describe("checkTimestreamFineGrainedAccess", () => {
	beforeEach(() => {
		mockTimestreamClient.reset();
		mockIAMClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for policies with table-level access", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: mockDatabases
			});

			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [mockPolicies[0]]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: encodeURIComponent(
						JSON.stringify({
							Version: "2012-10-17",
							Statement: [
								{
									Effect: "Allow",
									Action: ["timestream:WriteRecords"],
									Resource:
										"arn:aws:timestream:us-east-1:123456789012:database/test-db-1/table/specific-table"
								}
							]
						})
					)
				}
			});

			const result = await checkTimestreamFineGrainedAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toContain("table-level");
		});

		it("should return PASS for policies with column-level access", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: mockDatabases
			});

			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [mockPolicies[0]]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: encodeURIComponent(
						JSON.stringify({
							Version: "2012-10-17",
							Statement: [
								{
									Effect: "Allow",
									Action: ["timestream:Select"],
									Resource: "arn:aws:timestream:us-east-1:123456789012:database/test-db-1/table/*",
									Condition: {
										StringEquals: {
											"timestream:column": ["temperature", "humidity"]
										}
									}
								}
							]
						})
					)
				}
			});

			const result = await checkTimestreamFineGrainedAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toContain("column-level");
		});

		it("should return PASS for policies with row-level access", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: mockDatabases
			});

			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [mockPolicies[0]]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: encodeURIComponent(
						JSON.stringify({
							Version: "2012-10-17",
							Statement: [
								{
									Effect: "Allow",
									Action: ["timestream:Select"],
									Resource: "arn:aws:timestream:us-east-1:123456789012:database/test-db-1/table/*",
									Condition: {
										StringEquals: {
											"timestream:dimension": ["region", "device_id"]
										}
									}
								}
							]
						})
					)
				}
			});

			const result = await checkTimestreamFineGrainedAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toContain("row-level");
		});

		it("should return PASS and list all access controls when multiple are implemented", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: mockDatabases
			});

			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [mockPolicies[0]]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: encodeURIComponent(
						JSON.stringify({
							Version: "2012-10-17",
							Statement: [
								{
									Effect: "Allow",
									Action: ["timestream:Select"],
									Resource:
										"arn:aws:timestream:us-east-1:123456789012:database/test-db-1/table/specific-table",
									Condition: {
										StringEquals: {
											"timestream:column": ["temperature"],
											"timestream:dimension": ["region"]
										}
									}
								}
							]
						})
					)
				}
			});

			const result = await checkTimestreamFineGrainedAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toContain("table-level");
			expect(result.checks[0].message).toContain("column-level");
			expect(result.checks[0].message).toContain("row-level");
		});

		it("should return NOTAPPLICABLE when no databases exist", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: []
			});

			const result = await checkTimestreamFineGrainedAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for policies with broad access", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: mockDatabases
			});

			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [mockPolicies[1]]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: encodeURIComponent(
						JSON.stringify({
							Version: "2012-10-17",
							Statement: [
								{
									Effect: "Allow",
									Action: "timestream:*",
									Resource: "*"
								}
							]
						})
					)
				}
			});

			const result = await checkTimestreamFineGrainedAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("No fine-grained access controls found");
		});

		it("should handle mixed policy configurations", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: mockDatabases
			});

			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: mockPolicies
			});

			mockIAMClient
				.on(GetPolicyVersionCommand)
				.resolvesOnce({
					PolicyVersion: {
						Document: encodeURIComponent(
							JSON.stringify({
								Version: "2012-10-17",
								Statement: [
									{
										Effect: "Allow",
										Action: ["timestream:WriteRecords"],
										Resource:
											"arn:aws:timestream:us-east-1:123456789012:database/test-db-1/table/specific-table"
									}
								]
							})
						)
					}
				})
				.resolvesOnce({
					PolicyVersion: {
						Document: encodeURIComponent(
							JSON.stringify({
								Version: "2012-10-17",
								Statement: [
									{
										Effect: "Allow",
										Action: "timestream:*",
										Resource: "*"
									}
								]
							})
						)
					}
				});

			const result = await checkTimestreamFineGrainedAccess.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[1].message).toContain("Error analyzing policy");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListDatabases fails", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).rejects(new Error("Failed to list databases"));

			const result = await checkTimestreamFineGrainedAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to list databases");
		});

		it("should return ERROR when policy analysis fails", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: mockDatabases
			});

			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [mockPolicies[0]]
			});

			mockIAMClient.on(GetPolicyVersionCommand).rejects(new Error("Failed to get policy version"));

			const result = await checkTimestreamFineGrainedAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error analyzing policy");
		});
	});
});
