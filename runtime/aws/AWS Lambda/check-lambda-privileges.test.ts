// @ts-nocheck
import { LambdaClient, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import {
	IAMClient,
	ListAttachedRolePoliciesCommand,
	GetPolicyVersionCommand
} from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkLambdaPrivileges from "./check-lambda-privileges";

const mockLambdaClient = mockClient(LambdaClient);
const mockIAMClient = mockClient(IAMClient);

const mockLambdaFunction = {
	FunctionName: "test-function",
	FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:test-function",
	Role: "arn:aws:iam::123456789012:role/test-role"
};

const mockAdminPolicy = {
	Version: "2012-10-17",
	Statement: [
		{
			Effect: "Allow",
			Action: "*",
			Resource: "*"
		}
	]
};

const mockRestrictedPolicy = {
	Version: "2012-10-17",
	Statement: [
		{
			Effect: "Allow",
			Action: ["s3:GetObject", "s3:PutObject"],
			Resource: "arn:aws:s3:::my-bucket/*"
		}
	]
};

describe("checkLambdaPrivileges", () => {
	beforeEach(() => {
		mockLambdaClient.reset();
		mockIAMClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for Lambda functions with least privilege access", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [mockLambdaFunction]
			});

			mockIAMClient.on(ListAttachedRolePoliciesCommand).resolves({
				AttachedPolicies: [
					{
						PolicyArn: "arn:aws:iam::aws:policy/service-role/restricted-policy"
					}
				]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: encodeURIComponent(JSON.stringify(mockRestrictedPolicy))
				}
			});

			const result = await checkLambdaPrivileges.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-function");
		});

		it("should return NOTAPPLICABLE when no Lambda functions exist", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: []
			});

			const result = await checkLambdaPrivileges.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Lambda functions found");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for Lambda functions with administrative privileges", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [mockLambdaFunction]
			});

			mockIAMClient.on(ListAttachedRolePoliciesCommand).resolves({
				AttachedPolicies: [
					{
						PolicyArn: "arn:aws:iam::aws:policy/AdministratorAccess"
					}
				]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: encodeURIComponent(JSON.stringify(mockAdminPolicy))
				}
			});

			const result = await checkLambdaPrivileges.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Lambda function has administrative privileges");
		});

		it("should handle invalid role ARN format", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [
					{
						...mockLambdaFunction,
						Role: "arn:aws:iam::123456789012:role/"
					}
				]
			});

			const result = await checkLambdaPrivileges.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Invalid role ARN format");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListFunctions fails", async () => {
			mockLambdaClient.on(ListFunctionsCommand).rejects(new Error("Failed to list functions"));

			const result = await checkLambdaPrivileges.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Lambda functions");
		});

		it("should return ERROR when IAM operations fail", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [mockLambdaFunction]
			});

			mockIAMClient
				.on(ListAttachedRolePoliciesCommand)
				.rejects(new Error("Failed to list policies"));

			const result = await checkLambdaPrivileges.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking function permissions");
		});
	});
});
