// @ts-nocheck
import { DynamoDBClient, ListTablesCommand } from "@aws-sdk/client-dynamodb";
import { IAMClient, ListPoliciesCommand, GetPolicyVersionCommand } from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDynamoDBFGAC from "./check-dynamodb-fgac";

const mockDynamoDBClient = mockClient(DynamoDBClient);
const mockIAMClient = mockClient(IAMClient);

const mockPolicy = {
	PolicyName: "test-policy",
	Arn: "arn:aws:iam::123456789012:policy/test-policy",
	DefaultVersionId: "v1"
};

describe("checkDynamoDBFGAC", () => {
	beforeEach(() => {
		mockDynamoDBClient.reset();
		mockIAMClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for policies with proper FGAC", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({
				TableNames: ["table1", "table2"]
			});

			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [mockPolicy]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: encodeURIComponent(
						JSON.stringify({
							Version: "2012-10-17",
							Statement: [
								{
									Effect: "Allow",
									Action: ["dynamodb:GetItem"],
									Resource: "arn:aws:dynamodb:us-east-1:123456789012:table/table1"
								}
							]
						})
					)
				}
			});

			const result = await checkDynamoDBFGAC.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-policy");
		});

		it("should return NOTAPPLICABLE when no tables exist", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({
				TableNames: []
			});

			const result = await checkDynamoDBFGAC.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No DynamoDB tables found");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for policies with wildcard access", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({
				TableNames: ["table1"]
			});

			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [mockPolicy]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: encodeURIComponent(
						JSON.stringify({
							Version: "2012-10-17",
							Statement: [
								{
									Effect: "Allow",
									Action: "dynamodb:*",
									Resource: "*"
								}
							]
						})
					)
				}
			});

			const result = await checkDynamoDBFGAC.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Policy contains overly permissive DynamoDB access");
		});

		it("should return FAIL for policies with global wildcard", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({
				TableNames: ["table1"]
			});

			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [mockPolicy]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: encodeURIComponent(
						JSON.stringify({
							Version: "2012-10-17",
							Statement: [
								{
									Effect: "Allow",
									Action: "*",
									Resource: "*"
								}
							]
						})
					)
				}
			});

			const result = await checkDynamoDBFGAC.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when DynamoDB API call fails", async () => {
			mockDynamoDBClient.on(ListTablesCommand).rejects(new Error("API Error"));

			const result = await checkDynamoDBFGAC.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking DynamoDB FGAC");
		});

		it("should return ERROR when IAM API call fails", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({
				TableNames: ["table1"]
			});

			mockIAMClient.on(ListPoliciesCommand).rejects(new Error("IAM API Error"));

			const result = await checkDynamoDBFGAC.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
		});

		it("should handle invalid policy documents", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({
				TableNames: ["table1"]
			});

			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [mockPolicy]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: "invalid-json"
				}
			});

			const result = await checkDynamoDBFGAC.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking policy");
		});
	});
});
