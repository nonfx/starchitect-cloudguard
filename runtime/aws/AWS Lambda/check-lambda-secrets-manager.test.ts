// @ts-nocheck
import { LambdaClient, ListFunctionsCommand, GetFunctionCommand } from "@aws-sdk/client-lambda";
import { SecretsManagerClient, ListSecretsCommand } from "@aws-sdk/client-secrets-manager";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkLambdaSecretsManager from "./check-lambda-secrets-manager";

const mockLambdaClient = mockClient(LambdaClient);
const mockSecretsManagerClient = mockClient(SecretsManagerClient);

const mockSecretArn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret";

describe("checkLambdaSecretsManager", () => {
	beforeEach(() => {
		mockLambdaClient.reset();
		mockSecretsManagerClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Lambda uses Secrets Manager for credentials", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [
					{
						FunctionName: "test-function",
						FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:test-function"
					}
				]
			});

			mockLambdaClient.on(GetFunctionCommand).resolves({
				Configuration: {
					Environment: {
						Variables: {
							DB_PASSWORD: mockSecretArn
						}
					}
				}
			});

			mockSecretsManagerClient.on(ListSecretsCommand).resolves({
				SecretList: [
					{
						ARN: mockSecretArn
					}
				]
			});

			const result = await checkLambdaSecretsManager.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-function");
		});

		it("should return NOTAPPLICABLE when Lambda has no database credentials", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [
					{
						FunctionName: "test-function",
						FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:test-function"
					}
				]
			});

			mockLambdaClient.on(GetFunctionCommand).resolves({
				Configuration: {
					Environment: {
						Variables: {
							LOG_LEVEL: "info"
						}
					}
				}
			});

			mockSecretsManagerClient.on(ListSecretsCommand).resolves({
				SecretList: []
			});

			const result = await checkLambdaSecretsManager.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when Lambda stores credentials directly", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [
					{
						FunctionName: "test-function",
						FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:test-function"
					}
				]
			});

			mockLambdaClient.on(GetFunctionCommand).resolves({
				Configuration: {
					Environment: {
						Variables: {
							DB_PASSWORD: "plaintext-password"
						}
					}
				}
			});

			mockSecretsManagerClient.on(ListSecretsCommand).resolves({
				SecretList: []
			});

			const result = await checkLambdaSecretsManager.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("not managed by Secrets Manager");
		});

		it("should handle multiple functions with mixed compliance", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [
					{
						FunctionName: "compliant-function",
						FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:compliant-function"
					},
					{
						FunctionName: "non-compliant-function",
						FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:non-compliant-function"
					}
				]
			});

			mockLambdaClient
				.on(GetFunctionCommand, { FunctionName: "compliant-function" })
				.resolves({
					Configuration: {
						Environment: {
							Variables: {
								DB_PASSWORD: mockSecretArn
							}
						}
					}
				})
				.on(GetFunctionCommand, { FunctionName: "non-compliant-function" })
				.resolves({
					Configuration: {
						Environment: {
							Variables: {
								DB_PASSWORD: "plaintext-password"
							}
						}
					}
				});

			mockSecretsManagerClient.on(ListSecretsCommand).resolves({
				SecretList: [{ ARN: mockSecretArn }]
			});

			const result = await checkLambdaSecretsManager.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListFunctions fails", async () => {
			mockLambdaClient.on(ListFunctionsCommand).rejects(new Error("API Error"));

			const result = await checkLambdaSecretsManager.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Lambda functions");
		});

		it("should return ERROR for specific function when GetFunction fails", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [
					{
						FunctionName: "test-function",
						FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:test-function"
					}
				]
			});

			mockLambdaClient.on(GetFunctionCommand).rejects(new Error("Access Denied"));

			mockSecretsManagerClient.on(ListSecretsCommand).resolves({
				SecretList: []
			});

			const result = await checkLambdaSecretsManager.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking function configuration");
		});

		it("should return NOTAPPLICABLE when no Lambda functions exist", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: []
			});

			const result = await checkLambdaSecretsManager.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Lambda functions found in the region");
		});
	});
});
