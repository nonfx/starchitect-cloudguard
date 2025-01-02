//@ts-nocheck
import { LambdaClient, ListFunctionsCommand, GetFunctionCommand } from "@aws-sdk/client-lambda";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkLambdaInsights from "./check-lambda-insights";

const mockLambdaClient = mockClient(LambdaClient);

const mockFunction = {
	FunctionName: "test-function",
	FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:test-function"
};

const mockFunctionWithInsights = {
	Configuration: {
		Layers: [
			{
				Arn: "arn:aws:lambda:us-east-1:123456789012:layer:LambdaInsightsExtension:14"
			}
		]
	}
};

const mockFunctionWithoutInsights = {
	Configuration: {
		Layers: [
			{
				Arn: "arn:aws:lambda:us-east-1:123456789012:layer:OtherLayer:1"
			}
		]
	}
};

describe("checkLambdaInsights", () => {
	beforeEach(() => {
		mockLambdaClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Lambda has Insights enabled", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({ Functions: [mockFunction] });
			mockLambdaClient.on(GetFunctionCommand).resolves(mockFunctionWithInsights);

			const result = await checkLambdaInsights.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-function");
		});

		it("should handle multiple compliant functions", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [
					{ ...mockFunction, FunctionName: "func1" },
					{ ...mockFunction, FunctionName: "func2" }
				]
			});
			mockLambdaClient.on(GetFunctionCommand).resolves(mockFunctionWithInsights);

			const result = await checkLambdaInsights.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when Lambda does not have Insights enabled", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({ Functions: [mockFunction] });
			mockLambdaClient.on(GetFunctionCommand).resolves(mockFunctionWithoutInsights);

			const result = await checkLambdaInsights.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain(
				"does not have CloudWatch Lambda Insights enabled"
			);
		});

		it("should handle mixed compliance scenarios", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [
					{ ...mockFunction, FunctionName: "func1" },
					{ ...mockFunction, FunctionName: "func2" }
				]
			});
			mockLambdaClient
				.on(GetFunctionCommand)
				.resolves(mockFunctionWithInsights)
				.on(GetFunctionCommand, { FunctionName: "func2" })
				.resolves(mockFunctionWithoutInsights);

			const result = await checkLambdaInsights.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no functions exist", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({ Functions: [] });

			const result = await checkLambdaInsights.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});

		it("should return ERROR when ListFunctions fails", async () => {
			mockLambdaClient.on(ListFunctionsCommand).rejects(new Error("API Error"));

			const result = await checkLambdaInsights.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Lambda functions");
		});

		it("should handle pagination", async () => {
			mockLambdaClient
				.on(ListFunctionsCommand)
				.resolvesOnce({
					Functions: [mockFunction],
					NextMarker: "token1"
				})
				.resolvesOnce({
					Functions: [{ ...mockFunction, FunctionName: "func2" }]
				});
			mockLambdaClient.on(GetFunctionCommand).resolves(mockFunctionWithInsights);

			const result = await checkLambdaInsights.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
		});
	});
});
