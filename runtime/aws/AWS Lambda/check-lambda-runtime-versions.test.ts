// @ts-nocheck
import { LambdaClient, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkLambdaRuntimeVersions from "./check-lambda-runtime-versions";

const mockLambdaClient = mockClient(LambdaClient);

const mockSupportedFunction = {
	FunctionName: "test-function-1",
	FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:test-function-1",
	Runtime: "nodejs20.x"
};

const mockUnsupportedFunction = {
	FunctionName: "test-function-2",
	FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:test-function-2",
	Runtime: "nodejs14.x"
};

describe("checkLambdaRuntimeVersions", () => {
	beforeEach(() => {
		mockLambdaClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for functions with supported runtimes", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [mockSupportedFunction]
			});

			const result = await checkLambdaRuntimeVersions.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-function-1");
			expect(result.checks[0].resourceArn).toBe(mockSupportedFunction.FunctionArn);
		});

		it("should return NOTAPPLICABLE when no functions exist", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: []
			});

			const result = await checkLambdaRuntimeVersions.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Lambda functions found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for functions with unsupported runtimes", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [mockUnsupportedFunction]
			});

			const result = await checkLambdaRuntimeVersions.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("uses unsupported runtime");
		});

		it("should handle mixed supported and unsupported runtimes", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [mockSupportedFunction, mockUnsupportedFunction]
			});

			const result = await checkLambdaRuntimeVersions.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle functions with missing runtime information", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [
					{
						FunctionName: "test-function-3"
					}
				]
			});

			const result = await checkLambdaRuntimeVersions.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("missing name or runtime information");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockLambdaClient.on(ListFunctionsCommand).rejects(new Error("API Error"));

			const result = await checkLambdaRuntimeVersions.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Lambda functions");
		});

		it("should handle pagination", async () => {
			mockLambdaClient
				.on(ListFunctionsCommand)
				.resolvesOnce({
					Functions: [mockSupportedFunction],
					NextMarker: "token1"
				})
				.resolvesOnce({
					Functions: [mockUnsupportedFunction]
				});

			const result = await checkLambdaRuntimeVersions.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});
});
