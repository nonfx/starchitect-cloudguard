// @ts-nocheck
import { LambdaClient, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkLambdaUniqueIamRoles from "./check-lambda-unique-iam-roles";

const mockLambdaClient = mockClient(LambdaClient);

const mockFunctions = {
	uniqueRoles: [
		{
			FunctionName: "function1",
			Role: "arn:aws:iam::123456789012:role/unique-role-1"
		},
		{
			FunctionName: "function2",
			Role: "arn:aws:iam::123456789012:role/unique-role-2"
		}
	],
	sharedRoles: [
		{
			FunctionName: "function3",
			Role: "arn:aws:iam::123456789012:role/shared-role"
		},
		{
			FunctionName: "function4",
			Role: "arn:aws:iam::123456789012:role/shared-role"
		}
	],
	invalidFunction: {
		FunctionName: undefined,
		Role: undefined
	}
};

describe("checkLambdaUniqueIamRoles", () => {
	beforeEach(() => {
		mockLambdaClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when all functions have unique roles", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: mockFunctions.uniqueRoles
			});

			const result = await checkLambdaUniqueIamRoles.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});

		it("should return NOTAPPLICABLE when no functions exist", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: []
			});

			const result = await checkLambdaUniqueIamRoles.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Lambda functions found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when functions share roles", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: mockFunctions.sharedRoles
			});

			const result = await checkLambdaUniqueIamRoles.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("is shared with other functions");
		});

		it("should handle invalid function configurations", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({
				Functions: [mockFunctions.invalidFunction]
			});

			const result = await checkLambdaUniqueIamRoles.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Function missing name or role ARN");
		});
	});

	describe("Pagination and Error Handling", () => {
		it("should handle pagination correctly", async () => {
			mockLambdaClient
				.on(ListFunctionsCommand)
				.resolvesOnce({
					Functions: mockFunctions.uniqueRoles.slice(0, 1),
					NextMarker: "token1"
				})
				.resolvesOnce({
					Functions: mockFunctions.uniqueRoles.slice(1)
				});

			const result = await checkLambdaUniqueIamRoles.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});

		it("should return ERROR when API call fails", async () => {
			mockLambdaClient.on(ListFunctionsCommand).rejects(new Error("API Error"));

			const result = await checkLambdaUniqueIamRoles.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking Lambda functions: API Error");
		});
	});
});
