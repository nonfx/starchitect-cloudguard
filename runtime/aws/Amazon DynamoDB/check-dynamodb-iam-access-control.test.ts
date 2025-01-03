// @ts-nocheck
import { DynamoDBClient, ListTablesCommand } from "@aws-sdk/client-dynamodb";
import { IAMClient, ListRolePoliciesCommand, GetRolePolicyCommand } from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDynamoDBIAMAccessControl from "./check-dynamodb-iam-access-control";

const mockDynamoDBClient = mockClient(DynamoDBClient);
const mockIAMClient = mockClient(IAMClient);

const mockTableNames = ["table1", "table2"];
const mockRolePolicies = ["policy1", "policy2"];

describe("checkDynamoDBIAMAccessControl", () => {
	beforeEach(() => {
		mockDynamoDBClient.reset();
		mockIAMClient.reset();
		process.env.AWS_ACCOUNT_ID = "123456789012";
	});

	describe("Compliant Resources", () => {
		it("should return PASS when tables have proper IAM access controls", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({
				TableNames: mockTableNames
			});

			mockIAMClient.on(ListRolePoliciesCommand).resolves({
				PolicyNames: mockRolePolicies
			});

			const validPolicyDocument = encodeURIComponent(
				JSON.stringify({
					Statement: [
						{
							Effect: "Allow",
							Action: ["dynamodb:GetItem"],
							Resource: "arn:aws:dynamodb:us-east-1:123456789012:table/table1"
						}
					]
				})
			);

			mockIAMClient.on(GetRolePolicyCommand).resolves({
				PolicyDocument: validPolicyDocument
			});

			const result = await checkDynamoDBIAMAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("table1");
		});

		it("should return NOTAPPLICABLE when no tables exist", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({
				TableNames: []
			});

			const result = await checkDynamoDBIAMAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No DynamoDB tables found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when tables lack proper IAM controls", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({
				TableNames: mockTableNames
			});

			mockIAMClient.on(ListRolePoliciesCommand).resolves({
				PolicyNames: mockRolePolicies
			});

			const invalidPolicyDocument = encodeURIComponent(
				JSON.stringify({
					Statement: [
						{
							Effect: "Deny",
							Action: ["dynamodb:*"],
							Resource: "arn:aws:dynamodb:us-east-1:123456789012:table/table1"
						}
					]
				})
			);

			mockIAMClient.on(GetRolePolicyCommand).resolves({
				PolicyDocument: invalidPolicyDocument
			});

			const result = await checkDynamoDBIAMAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"DynamoDB table does not have proper IAM access controls"
			);
		});

		it("should handle mixed compliance scenarios", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({
				TableNames: mockTableNames
			});

			mockIAMClient.on(ListRolePoliciesCommand).resolves({
				PolicyNames: mockRolePolicies
			});

			mockIAMClient
				.on(GetRolePolicyCommand, { RoleName: "dynamodb-access-role", PolicyName: "policy1" })
				.resolves({
					PolicyDocument: encodeURIComponent(
						JSON.stringify({
							Statement: [
								{
									Effect: "Allow",
									Action: ["dynamodb:*"],
									Resource: "arn:aws:dynamodb:us-east-1:123456789012:table/table1"
								}
							]
						})
					)
				})
				.on(GetRolePolicyCommand, { RoleName: "dynamodb-access-role", PolicyName: "policy2" })
				.resolves({
					PolicyDocument: encodeURIComponent(
						JSON.stringify({
							Statement: [
								{
									Effect: "Deny",
									Action: ["dynamodb:*"],
									Resource: "arn:aws:dynamodb:us-east-1:123456789012:table/table2"
								}
							]
						})
					)
				});

			const result = await checkDynamoDBIAMAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListTables fails", async () => {
			mockDynamoDBClient.on(ListTablesCommand).rejects(new Error("Failed to list tables"));

			const result = await checkDynamoDBIAMAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to list tables");
		});

		it("should return ERROR when IAM policy check fails", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({
				TableNames: mockTableNames
			});

			mockIAMClient.on(ListRolePoliciesCommand).rejects(new Error("IAM API error"));

			const result = await checkDynamoDBIAMAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("IAM API error");
		});
	});
});
