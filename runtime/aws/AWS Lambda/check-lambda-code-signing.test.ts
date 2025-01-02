// @ts-nocheck
import {
	LambdaClient,
	ListFunctionsCommand,
	GetFunctionCodeSigningConfigCommand
} from "@aws-sdk/client-lambda";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkLambdaCodeSigning from "./check-lambda-code-signing";

const mockLambdaClient = mockClient(LambdaClient);

const mockFunction1 = {
	FunctionName: "test-function-1",
	FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:test-function-1"
};

const mockFunction2 = {
	FunctionName: "test-function-2",
	FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:test-function-2"
};

describe("checkLambdaCodeSigning", () => {
	beforeEach(() => {
		mockLambdaClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Code Signing is enabled", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({ Functions: [mockFunction1] });
			mockLambdaClient.on(GetFunctionCodeSigningConfigCommand).resolves({
				CodeSigningConfigArn: "arn:aws:lambda:us-east-1:123456789012:code-signing-config:csc-1"
			});

			const result = await checkLambdaCodeSigning.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe(mockFunction1.FunctionName);
		});

		it("should return NOTAPPLICABLE when no functions exist", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({ Functions: [] });

			const result = await checkLambdaCodeSigning.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Lambda functions found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when Code Signing is not enabled", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({ Functions: [mockFunction1] });
			mockLambdaClient.on(GetFunctionCodeSigningConfigCommand).resolves({});

			const result = await checkLambdaCodeSigning.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Lambda function does not have Code Signing enabled");
		});

		it("should handle mixed compliance states", async () => {
			mockLambdaClient
				.on(ListFunctionsCommand)
				.resolves({ Functions: [mockFunction1, mockFunction2] });
			mockLambdaClient
				.on(GetFunctionCodeSigningConfigCommand, { FunctionName: mockFunction1.FunctionName })
				.resolves({
					CodeSigningConfigArn: "arn:aws:lambda:us-east-1:123456789012:code-signing-config:csc-1"
				})
				.on(GetFunctionCodeSigningConfigCommand, { FunctionName: mockFunction2.FunctionName })
				.resolves({});

			const result = await checkLambdaCodeSigning.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should handle ListFunctions API errors", async () => {
			mockLambdaClient.on(ListFunctionsCommand).rejects(new Error("API Error"));

			const result = await checkLambdaCodeSigning.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Lambda functions");
		});

		it("should handle GetFunction API errors", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({ Functions: [mockFunction1] });
			mockLambdaClient.on(GetFunctionCodeSigningConfigCommand).rejects(new Error("Access Denied"));

			const result = await checkLambdaCodeSigning.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking function details");
		});

		it("should handle pagination", async () => {
			mockLambdaClient
				.on(ListFunctionsCommand)
				.resolvesOnce({
					Functions: [mockFunction1],
					NextMarker: "token1"
				})
				.resolvesOnce({
					Functions: [mockFunction2]
				});
			mockLambdaClient.on(GetFunctionCodeSigningConfigCommand).resolves({
				CodeSigningConfigArn: "arn:aws:lambda:us-east-1:123456789012:code-signing-config:csc-1"
			});

			const result = await checkLambdaCodeSigning.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});
});
