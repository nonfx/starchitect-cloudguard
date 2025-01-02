// @ts-nocheck
import { LambdaClient, ListFunctionsCommand, GetFunctionCommand } from "@aws-sdk/client-lambda";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkLambdaRuntime from "./check-lambda-runtime";

const mockLambdaClient = mockClient(LambdaClient);

const mockFunction = (name: string, runtime: string, packageType: string = "Zip") => ({
	FunctionName: name,
	FunctionArn: `arn:aws:lambda:us-east-1:123456789012:function:${name}`,
	Runtime: runtime,
	PackageType: packageType
});

describe("checkLambdaRuntime", () => {
	beforeEach(() => {
		mockLambdaClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for functions with supported runtimes", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [mockFunction("func1", "nodejs20.x"), mockFunction("func2", "python3.12")]
			});

			mockLambdaClient
				.on(GetFunctionCommand, { FunctionName: "func1" })
				.resolves({
					Configuration: {
						Runtime: "nodejs20.x",
						PackageType: "Zip"
					}
				})
				.on(GetFunctionCommand, { FunctionName: "func2" })
				.resolves({
					Configuration: {
						Runtime: "python3.12",
						PackageType: "Zip"
					}
				});

			const result = await checkLambdaRuntime.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});

		it("should return PASS for container image functions", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [mockFunction("container-func", null, "Image")]
			});

			mockLambdaClient.on(GetFunctionCommand).resolves({
				Configuration: {
					PackageType: "Image"
				}
			});

			const result = await checkLambdaRuntime.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toContain("container image packaging");
		});

		it("should return NOTAPPLICABLE when no functions exist", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({ Functions: [] });

			const result = await checkLambdaRuntime.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for functions with unsupported runtimes", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [mockFunction("old-func", "nodejs14.x")]
			});

			mockLambdaClient.on(GetFunctionCommand).resolves({
				Configuration: {
					Runtime: "nodejs14.x",
					PackageType: "Zip"
				}
			});

			const result = await checkLambdaRuntime.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("unsupported runtime");
		});

		it("should handle mixed compliance scenarios", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [mockFunction("new-func", "nodejs20.x"), mockFunction("old-func", "python2.7")]
			});

			mockLambdaClient
				.on(GetFunctionCommand, { FunctionName: "new-func" })
				.resolves({
					Configuration: {
						Runtime: "nodejs20.x",
						PackageType: "Zip"
					}
				})
				.on(GetFunctionCommand, { FunctionName: "old-func" })
				.resolves({
					Configuration: {
						Runtime: "python2.7",
						PackageType: "Zip"
					}
				});

			const result = await checkLambdaRuntime.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should handle ListFunctions API errors", async () => {
			mockLambdaClient.on(ListFunctionsCommand).rejects(new Error("API Error"));

			const result = await checkLambdaRuntime.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Lambda functions");
		});

		it("should handle GetFunction API errors", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [mockFunction("error-func", "nodejs20.x")]
			});

			mockLambdaClient.on(GetFunctionCommand).rejects(new Error("Function not found"));

			const result = await checkLambdaRuntime.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking function details");
		});

		it("should handle pagination", async () => {
			mockLambdaClient
				.on(ListFunctionsCommand)
				.resolvesOnce({
					Functions: [mockFunction("func1", "nodejs20.x")],
					NextMarker: "token1"
				})
				.resolvesOnce({
					Functions: [mockFunction("func2", "python3.12")]
				});

			mockLambdaClient
				.on(GetFunctionCommand, { FunctionName: "func1" })
				.resolves({
					Configuration: {
						Runtime: "nodejs20.x",
						PackageType: "Zip"
					}
				})
				.on(GetFunctionCommand, { FunctionName: "func2" })
				.resolves({
					Configuration: {
						Runtime: "python3.12",
						PackageType: "Zip"
					}
				});

			const result = await checkLambdaRuntime.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});
});
