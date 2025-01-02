// @ts-nocheck
import { LambdaClient, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import {
	IAMClient,
	ListAttachedRolePoliciesCommand,
	GetPolicyVersionCommand
} from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkLambdaLeastPrivilege from "./check-lambda-least-privilege";

const mockLambdaClient = mockClient(LambdaClient);
const mockIAMClient = mockClient(IAMClient);

const mockLambdaFunction = {
	FunctionName: "test-function",
	FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:test-function",
	Role: "arn:aws:iam::123456789012:role/test-role"
};

const mockLeastPrivilegePolicy = {
	Version: "2012-10-17",
	Statement: [
		{
			Effect: "Allow",
			Action: ["s3:GetObject", "s3:PutObject"],
			Resource: "arn:aws:s3:::my-bucket/*"
		}
	]
};

const mockOverlyPermissivePolicy = {
	Version: "2012-10-17",
	Statement: [
		{
			Effect: "Allow",
			Action: ["s3:*"],
			Resource: "*"
		}
	]
};

describe("checkLambdaLeastPrivilege", () => {
	beforeEach(() => {
		mockLambdaClient.reset();
		mockIAMClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Lambda function has least privilege policies", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [mockLambdaFunction]
			});

			mockIAMClient.on(ListAttachedRolePoliciesCommand).resolves({
				AttachedPolicies: [
					{
						PolicyArn: "arn:aws:iam::aws:policy/service-role/test-policy"
					}
				]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: encodeURIComponent(JSON.stringify(mockLeastPrivilegePolicy))
				}
			});

			const result = await checkLambdaLeastPrivilege.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-function");
		});

		it("should return NOTAPPLICABLE when no Lambda functions exist", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: []
			});

			const result = await checkLambdaLeastPrivilege.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Lambda functions found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when Lambda function has overly permissive policies", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [mockLambdaFunction]
			});

			mockIAMClient.on(ListAttachedRolePoliciesCommand).resolves({
				AttachedPolicies: [
					{
						PolicyArn: "arn:aws:iam::aws:policy/service-role/test-policy"
					}
				]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: encodeURIComponent(JSON.stringify(mockOverlyPermissivePolicy))
				}
			});

			const result = await checkLambdaLeastPrivilege.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Lambda function has overly permissive IAM policies");
		});

		it("should handle Lambda functions without roles", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [
					{
						FunctionName: "no-role-function"
					}
				]
			});

			const result = await checkLambdaLeastPrivilege.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Function missing name or role ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when Lambda API call fails", async () => {
			mockLambdaClient.on(ListFunctionsCommand).rejects(new Error("Failed to list functions"));

			const result = await checkLambdaLeastPrivilege.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to list functions");
		});

		it("should return ERROR when IAM API calls fail", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [mockLambdaFunction]
			});

			mockIAMClient
				.on(ListAttachedRolePoliciesCommand)
				.rejects(new Error("Failed to list policies"));

			const result = await checkLambdaLeastPrivilege.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to list policies");
		});
	});

	describe("Multiple Resources", () => {
		it("should handle multiple Lambda functions with different configurations", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [
					mockLambdaFunction,
					{
						FunctionName: "test-function-2",
						FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:test-function-2",
						Role: "arn:aws:iam::123456789012:role/test-role-2"
					}
				]
			});

			mockIAMClient.on(ListAttachedRolePoliciesCommand).resolves({
				AttachedPolicies: [
					{
						PolicyArn: "arn:aws:iam::aws:policy/service-role/test-policy"
					}
				]
			});

			mockIAMClient
				.on(GetPolicyVersionCommand)
				.resolvesOnce({
					PolicyVersion: {
						Document: encodeURIComponent(JSON.stringify(mockLeastPrivilegePolicy))
					}
				})
				.resolvesOnce({
					PolicyVersion: {
						Document: encodeURIComponent(JSON.stringify(mockOverlyPermissivePolicy))
					}
				});

			const result = await checkLambdaLeastPrivilege.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});
});
