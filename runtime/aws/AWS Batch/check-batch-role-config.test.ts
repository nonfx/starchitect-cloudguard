//@ts-nocheck
import { BatchClient, DescribeComputeEnvironmentsCommand } from "@aws-sdk/client-batch";
import { IAMClient, GetRoleCommand } from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkBatchRoleConfig from "./check-batch-role-config";

const mockBatchClient = mockClient(BatchClient);
const mockIAMClient = mockClient(IAMClient);

const mockComputeEnvironment = {
	computeEnvironmentName: "test-env",
	serviceRole: "arn:aws:iam::123456789012:role/BatchServiceRole"
};

const mockRoleWithConditions = {
	Role: {
		AssumeRolePolicyDocument: encodeURIComponent(
			JSON.stringify({
				Version: "2012-10-17",
				Statement: [
					{
						Effect: "Allow",
						Principal: { Service: "batch.amazonaws.com" },
						Action: "sts:AssumeRole",
						Condition: {
							StringEquals: { "aws:SourceAccount": "123456789012" },
							StringLike: { "aws:SourceArn": "arn:aws:batch:*:123456789012:*" }
						}
					}
				]
			})
		)
	}
};

const mockRoleWithoutConditions = {
	Role: {
		AssumeRolePolicyDocument: encodeURIComponent(
			JSON.stringify({
				Version: "2012-10-17",
				Statement: [
					{
						Effect: "Allow",
						Principal: { Service: "batch.amazonaws.com" },
						Action: "sts:AssumeRole"
					}
				]
			})
		)
	}
};

describe("checkBatchRoleConfig", () => {
	beforeEach(() => {
		mockBatchClient.reset();
		mockIAMClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when compute environment role has required conditions", async () => {
			mockBatchClient.on(DescribeComputeEnvironmentsCommand).resolves({
				computeEnvironments: [mockComputeEnvironment]
			});
			mockIAMClient.on(GetRoleCommand).resolves(mockRoleWithConditions);

			const result = await checkBatchRoleConfig.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-env");
		});

		it("should return NOTAPPLICABLE when no compute environments exist", async () => {
			mockBatchClient.on(DescribeComputeEnvironmentsCommand).resolves({
				computeEnvironments: []
			});

			const result = await checkBatchRoleConfig.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toContain("No AWS Batch compute environments found");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when role is missing required conditions", async () => {
			mockBatchClient.on(DescribeComputeEnvironmentsCommand).resolves({
				computeEnvironments: [mockComputeEnvironment]
			});
			mockIAMClient.on(GetRoleCommand).resolves(mockRoleWithoutConditions);

			const result = await checkBatchRoleConfig.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("missing required condition keys");
		});

		it("should return FAIL when role is missing trust policy", async () => {
			mockBatchClient.on(DescribeComputeEnvironmentsCommand).resolves({
				computeEnvironments: [mockComputeEnvironment]
			});
			mockIAMClient.on(GetRoleCommand).resolves({ Role: {} });

			const result = await checkBatchRoleConfig.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("missing trust policy");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when BatchClient fails", async () => {
			mockBatchClient
				.on(DescribeComputeEnvironmentsCommand)
				.rejects(new Error("Failed to describe compute environments"));

			const result = await checkBatchRoleConfig.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to describe compute environments");
		});

		it("should return ERROR when IAMClient fails", async () => {
			mockBatchClient.on(DescribeComputeEnvironmentsCommand).resolves({
				computeEnvironments: [mockComputeEnvironment]
			});
			mockIAMClient.on(GetRoleCommand).rejects(new Error("Failed to get role"));

			const result = await checkBatchRoleConfig.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to get role");
		});
	});
});
