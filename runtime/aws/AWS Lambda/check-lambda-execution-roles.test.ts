// @ts-nocheck
import { LambdaClient, ListFunctionsCommand, GetFunctionCommand } from "@aws-sdk/client-lambda";
import { IAMClient, GetRoleCommand } from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkLambdaExecutionRoles from "./check-lambda-execution-roles";

const mockLambdaClient = mockClient(LambdaClient);
const mockIAMClient = mockClient(IAMClient);

const mockFunction1 = {
	FunctionName: "test-function-1",
	FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:test-function-1",
	Role: "arn:aws:iam::123456789012:role/lambda-role-1"
};

const mockFunction2 = {
	FunctionName: "test-function-2",
	FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:test-function-2",
	Role: "arn:aws:iam::123456789012:role/lambda-role-2"
};

describe("checkLambdaExecutionRoles", () => {
	beforeEach(() => {
		mockLambdaClient.reset();
		mockIAMClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when all Lambda functions have valid execution roles", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [mockFunction1, mockFunction2]
			});

			mockLambdaClient.on(GetFunctionCommand).resolves({
				Configuration: { Role: mockFunction1.Role }
			});

			mockIAMClient.on(GetRoleCommand).resolves({
				Role: { RoleName: "lambda-role-1" }
			});

			const result = await checkLambdaExecutionRoles.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-function-1");
		});

		it("should return NOTAPPLICABLE when no Lambda functions exist", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: []
			});

			const result = await checkLambdaExecutionRoles.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Lambda functions found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when function references non-existent role", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [mockFunction1]
			});

			mockLambdaClient.on(GetFunctionCommand).resolves({
				Configuration: { Role: mockFunction1.Role }
			});

			mockIAMClient.on(GetRoleCommand).rejects({
				name: "NoSuchEntityException"
			});

			const result = await checkLambdaExecutionRoles.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Function references a non-existent execution role");
		});

		it("should return FAIL when function has no role configured", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [mockFunction1]
			});

			mockLambdaClient.on(GetFunctionCommand).resolves({
				Configuration: { Role: undefined }
			});

			const result = await checkLambdaExecutionRoles.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Function does not have an execution role configured");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListFunctions fails", async () => {
			mockLambdaClient.on(ListFunctionsCommand).rejects(new Error("API Error"));

			const result = await checkLambdaExecutionRoles.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Lambda functions");
		});

		it("should return ERROR when GetFunction fails", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [mockFunction1]
			});

			mockLambdaClient.on(GetFunctionCommand).rejects(new Error("Configuration Error"));

			const result = await checkLambdaExecutionRoles.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking function configuration");
		});

		it("should return ERROR when role ARN is invalid", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [mockFunction1]
			});

			// Return a role ARN without a role name after the last "/"
			mockLambdaClient.on(GetFunctionCommand).resolves({
				Configuration: { Role: "arn:aws:iam::123456789012:role/" }
			});

			const result = await checkLambdaExecutionRoles.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Invalid role ARN format");
		});
	});
});
