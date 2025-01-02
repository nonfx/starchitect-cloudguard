//@ts-nocheck
import { LambdaClient, GetPolicyCommand, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkLambdaPublicAccess from "./check-lambda-public-access";

const mockLambdaClient = mockClient(LambdaClient);

const mockFunctions = [
	{
		FunctionName: "private-function",
		FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:private-function"
	},
	{
		FunctionName: "public-function",
		FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:public-function"
	},
	{
		FunctionName: "s3-function",
		FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:s3-function"
	}
];

const privatePolicy = {
	Policy: JSON.stringify({
		Version: "2012-10-17",
		Statement: [
			{
				Effect: "Allow",
				Principal: { AWS: "arn:aws:iam::123456789012:role/specific-role" },
				Action: "lambda:InvokeFunction",
				Resource: mockFunctions[0].FunctionArn
			}
		]
	})
};

const publicPolicy = {
	Policy: JSON.stringify({
		Version: "2012-10-17",
		Statement: [
			{
				Effect: "Allow",
				Principal: "*",
				Action: "lambda:InvokeFunction",
				Resource: mockFunctions[1].FunctionArn
			}
		]
	})
};

const s3PolicyWithCondition = {
	Policy: JSON.stringify({
		Version: "2012-10-17",
		Statement: [
			{
				Effect: "Allow",
				Principal: { Service: "s3.amazonaws.com" },
				Action: "lambda:InvokeFunction",
				Resource: mockFunctions[2].FunctionArn,
				Condition: {
					StringEquals: {
						"aws:SourceAccount": "123456789012"
					}
				}
			}
		]
	})
};

describe("checkLambdaPublicAccess", () => {
	beforeEach(() => {
		mockLambdaClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for private function policy", async () => {
			mockLambdaClient
				.on(ListFunctionsCommand)
				.resolves({ Functions: [mockFunctions[0]] })
				.on(GetPolicyCommand)
				.resolves(privatePolicy);

			const result = await checkLambdaPublicAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("private-function");
		});

		it("should return PASS for S3 function with proper condition", async () => {
			mockLambdaClient
				.on(ListFunctionsCommand)
				.resolves({ Functions: [mockFunctions[2]] })
				.on(GetPolicyCommand)
				.resolves(s3PolicyWithCondition);

			const result = await checkLambdaPublicAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("s3-function");
		});

		it("should return PASS when function has no policy", async () => {
			mockLambdaClient
				.on(ListFunctionsCommand)
				.resolves({ Functions: [mockFunctions[0]] })
				.on(GetPolicyCommand)
				.rejects({ name: "ResourceNotFoundException" });

			const result = await checkLambdaPublicAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toBe("No resource policy attached");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for public function policy", async () => {
			mockLambdaClient
				.on(ListFunctionsCommand)
				.resolves({ Functions: [mockFunctions[1]] })
				.on(GetPolicyCommand)
				.resolves(publicPolicy);

			const result = await checkLambdaPublicAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("public access permissions");
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no functions exist", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({ Functions: [] });

			const result = await checkLambdaPublicAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Lambda functions found in the region");
		});

		it("should return ERROR when ListFunctions fails", async () => {
			mockLambdaClient.on(ListFunctionsCommand).rejects(new Error("API Error"));

			const result = await checkLambdaPublicAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Lambda functions");
		});

		it("should return ERROR when GetPolicy fails unexpectedly", async () => {
			mockLambdaClient
				.on(ListFunctionsCommand)
				.resolves({ Functions: [mockFunctions[0]] })
				.on(GetPolicyCommand)
				.rejects(new Error("Unexpected error"));

			const result = await checkLambdaPublicAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking function policy");
		});
	});
});
