//@ts-nocheck
import { BatchClient, DescribeJobDefinitionsCommand } from "@aws-sdk/client-batch";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkBatchCloudWatchLogs from "./check-batch-cloudwatch-logs";

const mockBatchClient = mockClient(BatchClient);

const mockJobDefinitionWithCloudWatchLogs = {
	jobDefinitionName: "test-job-1",
	jobDefinitionArn: "arn:aws:batch:us-east-1:123456789012:job-definition/test-job-1:1",
	containerProperties: {
		logConfiguration: {
			logDriver: "awslogs"
		}
	}
};

const mockJobDefinitionWithoutCloudWatchLogs = {
	jobDefinitionName: "test-job-2",
	jobDefinitionArn: "arn:aws:batch:us-east-1:123456789012:job-definition/test-job-2:1",
	containerProperties: {
		logConfiguration: {
			logDriver: "json-file"
		}
	}
};

describe("checkBatchCloudWatchLogs", () => {
	beforeEach(() => {
		mockBatchClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when job definition uses CloudWatch Logs", async () => {
			mockBatchClient.on(DescribeJobDefinitionsCommand).resolves({
				jobDefinitions: [mockJobDefinitionWithCloudWatchLogs]
			});

			const result = await checkBatchCloudWatchLogs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-job-1");
			expect(result.checks[0].resourceArn).toBe(
				mockJobDefinitionWithCloudWatchLogs.jobDefinitionArn
			);
		});

		it("should return NOTAPPLICABLE when no job definitions exist", async () => {
			mockBatchClient.on(DescribeJobDefinitionsCommand).resolves({
				jobDefinitions: []
			});

			const result = await checkBatchCloudWatchLogs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No AWS Batch job definitions found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when job definition does not use CloudWatch Logs", async () => {
			mockBatchClient.on(DescribeJobDefinitionsCommand).resolves({
				jobDefinitions: [mockJobDefinitionWithoutCloudWatchLogs]
			});

			const result = await checkBatchCloudWatchLogs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Batch job definition is not configured to use CloudWatch Logs"
			);
		});

		it("should handle mixed compliance results", async () => {
			mockBatchClient.on(DescribeJobDefinitionsCommand).resolves({
				jobDefinitions: [
					mockJobDefinitionWithCloudWatchLogs,
					mockJobDefinitionWithoutCloudWatchLogs
				]
			});

			const result = await checkBatchCloudWatchLogs.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockBatchClient.on(DescribeJobDefinitionsCommand).rejects(new Error("API Error"));

			const result = await checkBatchCloudWatchLogs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Batch job definitions");
		});

		it("should handle malformed job definitions", async () => {
			mockBatchClient.on(DescribeJobDefinitionsCommand).resolves({
				jobDefinitions: [
					{
						jobDefinitionName: "malformed-job",
						jobDefinitionArn: "arn:aws:batch:us-east-1:123456789012:job-definition/malformed-job:1",
						containerProperties: "invalid-json"
					}
				]
			});

			const result = await checkBatchCloudWatchLogs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error parsing container properties");
		});

		it("should handle missing container properties", async () => {
			mockBatchClient.on(DescribeJobDefinitionsCommand).resolves({
				jobDefinitions: [
					{
						jobDefinitionName: "incomplete-job",
						jobDefinitionArn: "arn:aws:batch:us-east-1:123456789012:job-definition/incomplete-job:1"
					}
				]
			});

			const result = await checkBatchCloudWatchLogs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Job definition missing container properties");
		});
	});
});
