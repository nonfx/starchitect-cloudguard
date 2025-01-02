// @ts-nocheck
import { LambdaClient, GetPolicyCommand, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkLambdaExposure from "./check-lambda-exposure";

const mockLambdaClient = mockClient(LambdaClient);

const mockFunctions = [
	{
		FunctionName: "test-function-1",
		FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:test-function-1"
	},
	{
		FunctionName: "test-function-2",
		FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:test-function-2"
	}
];

const publicPolicy = JSON.stringify({
	Statement: [
		{
			Effect: "Allow",
			Principal: "*",
			Action: "lambda:InvokeFunction",
			Resource: mockFunctions[0].FunctionArn
		}
	]
});

const restrictedPolicy = JSON.stringify({
	Statement: [
		{
			Effect: "Allow",
			Principal: {
				AWS: "arn:aws:iam::123456789012:root"
			},
			Action: "lambda:InvokeFunction",
			Resource: mockFunctions[1].FunctionArn
		}
	]
});

describe("checkLambdaExposure", () => {
	beforeEach(() => {
		mockLambdaClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for functions with no policy", async () => {
			mockLambdaClient
				.on(ListFunctionsCommand)
				.resolves({ Functions: [mockFunctions[0]] })
				.on(GetPolicyCommand)
				.rejects({ name: "ResourceNotFoundException" });

			const result = await checkLambdaExposure.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe(mockFunctions[0].FunctionName);
		});

		it("should return PASS for functions with restricted policy", async () => {
			mockLambdaClient
				.on(ListFunctionsCommand)
				.resolves({ Functions: [mockFunctions[1]] })
				.on(GetPolicyCommand)
				.resolves({ Policy: restrictedPolicy });

			const result = await checkLambdaExposure.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe(mockFunctions[1].FunctionName);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for publicly accessible functions", async () => {
			mockLambdaClient
				.on(ListFunctionsCommand)
				.resolves({ Functions: [mockFunctions[0]] })
				.on(GetPolicyCommand)
				.resolves({ Policy: publicPolicy });

			const result = await checkLambdaExposure.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Lambda function is publicly accessible");
		});

		it("should handle mixed compliance scenarios", async () => {
			mockLambdaClient
				.on(ListFunctionsCommand)
				.resolves({ Functions: mockFunctions })
				.on(GetPolicyCommand, { FunctionName: mockFunctions[0].FunctionName })
				.resolves({ Policy: publicPolicy })
				.on(GetPolicyCommand, { FunctionName: mockFunctions[1].FunctionName })
				.resolves({ Policy: restrictedPolicy });

			const result = await checkLambdaExposure.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no functions exist", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({ Functions: [] });

			const result = await checkLambdaExposure.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Lambda functions found in the region");
		});

		it("should return ERROR when ListFunctions fails", async () => {
			mockLambdaClient.on(ListFunctionsCommand).rejects(new Error("API Error"));

			const result = await checkLambdaExposure.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Lambda functions");
		});

		it("should return ERROR when GetPolicy fails unexpectedly", async () => {
			mockLambdaClient
				.on(ListFunctionsCommand)
				.resolves({ Functions: [mockFunctions[0]] })
				.on(GetPolicyCommand)
				.rejects(new Error("Access Denied"));

			const result = await checkLambdaExposure.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking function policy");
		});

		it("should handle malformed function data", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({ Functions: [{}] });

			const result = await checkLambdaExposure.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Function found without name or ARN");
		});
	});
});
