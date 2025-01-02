// @ts-nocheck
import { LambdaClient, ListFunctionsCommand, GetFunctionCommand } from "@aws-sdk/client-lambda";
import { EC2Client, DescribeSubnetsCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkLambdaVpcMultiAz from "./check-lambda-vpc-multi-az";

const mockLambdaClient = mockClient(LambdaClient);
const mockEC2Client = mockClient(EC2Client);

const mockFunction1 = {
	FunctionName: "test-function-1",
	FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:test-function-1"
};

const mockFunction2 = {
	FunctionName: "test-function-2",
	FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:test-function-2"
};

describe("checkLambdaVpcMultiAz", () => {
	beforeEach(() => {
		mockLambdaClient.reset();
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Lambda function uses multiple AZs", async () => {
			mockLambdaClient
				.on(ListFunctionsCommand)
				.resolves({ Functions: [mockFunction1] })
				.on(GetFunctionCommand)
				.resolves({
					Configuration: {
						VpcConfig: {
							SubnetIds: ["subnet-1", "subnet-2"]
						}
					}
				});

			mockEC2Client.on(DescribeSubnetsCommand).resolves({
				Subnets: [
					{ SubnetId: "subnet-1", AvailabilityZone: "us-east-1a" },
					{ SubnetId: "subnet-2", AvailabilityZone: "us-east-1b" }
				]
			});

			const result = await checkLambdaVpcMultiAz.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-function-1");
		});

		it("should return NOTAPPLICABLE for non-VPC Lambda functions", async () => {
			mockLambdaClient
				.on(ListFunctionsCommand)
				.resolves({ Functions: [mockFunction1] })
				.on(GetFunctionCommand)
				.resolves({
					Configuration: {
						VpcConfig: { SubnetIds: [] }
					}
				});

			const result = await checkLambdaVpcMultiAz.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("Function is not VPC-connected");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when Lambda function uses single AZ", async () => {
			mockLambdaClient
				.on(ListFunctionsCommand)
				.resolves({ Functions: [mockFunction1] })
				.on(GetFunctionCommand)
				.resolves({
					Configuration: {
						VpcConfig: {
							SubnetIds: ["subnet-1"]
						}
					}
				});

			mockEC2Client.on(DescribeSubnetsCommand).resolves({
				Subnets: [{ SubnetId: "subnet-1", AvailabilityZone: "us-east-1a" }]
			});

			const result = await checkLambdaVpcMultiAz.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("Function uses 1 AZ(s)");
		});

		it("should handle mixed compliance scenarios", async () => {
			mockLambdaClient
				.on(ListFunctionsCommand)
				.resolves({ Functions: [mockFunction1, mockFunction2] })
				.on(GetFunctionCommand, { FunctionName: "test-function-1" })
				.resolves({
					Configuration: {
						VpcConfig: {
							SubnetIds: ["subnet-1", "subnet-2"]
						}
					}
				})
				.on(GetFunctionCommand, { FunctionName: "test-function-2" })
				.resolves({
					Configuration: {
						VpcConfig: {
							SubnetIds: ["subnet-3"]
						}
					}
				});

			mockEC2Client
				.on(DescribeSubnetsCommand, { SubnetIds: ["subnet-1", "subnet-2"] })
				.resolves({
					Subnets: [
						{ SubnetId: "subnet-1", AvailabilityZone: "us-east-1a" },
						{ SubnetId: "subnet-2", AvailabilityZone: "us-east-1b" }
					]
				})
				.on(DescribeSubnetsCommand, { SubnetIds: ["subnet-3"] })
				.resolves({
					Subnets: [{ SubnetId: "subnet-3", AvailabilityZone: "us-east-1a" }]
				});

			const result = await checkLambdaVpcMultiAz.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListFunctions fails", async () => {
			mockLambdaClient.on(ListFunctionsCommand).rejects(new Error("API Error"));

			const result = await checkLambdaVpcMultiAz.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Lambda functions");
		});

		it("should return ERROR when GetFunction fails", async () => {
			mockLambdaClient
				.on(ListFunctionsCommand)
				.resolves({ Functions: [mockFunction1] })
				.on(GetFunctionCommand)
				.rejects(new Error("Function not found"));

			const result = await checkLambdaVpcMultiAz.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking function");
		});

		it("should return NOTAPPLICABLE when no functions exist", async () => {
			mockLambdaClient.on(ListFunctionsCommand).resolves({ Functions: [] });

			const result = await checkLambdaVpcMultiAz.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Lambda functions found in the region");
		});
	});
});
