import { CloudWatchLogsClient, DescribeLogGroupsCommand } from "@aws-sdk/client-cloudwatch-logs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkCloudWatchLogGroupRetention from "./aws_cloudwatch_log_group_retention";

const mockCloudWatchLogsClient = mockClient(CloudWatchLogsClient);

const mockLogGroups = [
    {
        logGroupName: "test-group-1",
        arn: "arn:aws:logs:us-east-1:123456789012:log-group:test-group-1",
        retentionInDays: 365
    },
    {
        logGroupName: "test-group-2",
        arn: "arn:aws:logs:us-east-1:123456789012:log-group:test-group-2",
        retentionInDays: 30
    },
    {
        logGroupName: "test-group-3",
        arn: "arn:aws:logs:us-east-1:123456789012:log-group:test-group-3",
        retentionInDays: 0
    }
];

describe("checkCloudWatchLogGroupRetention", () => {
    beforeEach(() => {
        mockCloudWatchLogsClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS for log groups with sufficient retention period", async () => {
            mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
                logGroups: [mockLogGroups[0]]
            });

            const result = await checkCloudWatchLogGroupRetention.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("test-group-1");
        });

        it("should return PASS for log groups with never expire retention", async () => {
            mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
                logGroups: [mockLogGroups[2]]
            });

            const result = await checkCloudWatchLogGroupRetention.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].message).toBe("Retention set to never expire");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL for log groups with insufficient retention period", async () => {
            mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
                logGroups: [mockLogGroups[1]]
            });

            const result = await checkCloudWatchLogGroupRetention.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain("Retention period (30 days) is less than required");
        });

        it("should return FAIL for log groups with undefined retention", async () => {
            mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
                logGroups: [{
                    logGroupName: "test-group-4",
                    arn: "arn:aws:logs:us-east-1:123456789012:log-group:test-group-4"
                }]
            });

            const result = await checkCloudWatchLogGroupRetention.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("No retention period configured (logs retained indefinitely)");
        });
    });

    describe("Edge Cases", () => {
        it("should return NOTAPPLICABLE when no log groups exist", async () => {
            mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
                logGroups: []
            });

            const result = await checkCloudWatchLogGroupRetention.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No CloudWatch log groups found in the region");
        });

        it("should return ERROR when log group is missing ARN", async () => {
            mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
                logGroups: [{
                    logGroupName: "test-group-5",
                    retentionInDays: 365
                }]
            });

            const result = await checkCloudWatchLogGroupRetention.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Log group missing ARN");
        });
    });

    describe("Pagination", () => {
        it("should handle pagination correctly", async () => {
            mockCloudWatchLogsClient
                .on(DescribeLogGroupsCommand)
                .resolvesOnce({
                    logGroups: [mockLogGroups[0]],
                    nextToken: "token1"
                })
                .resolvesOnce({
                    logGroups: [mockLogGroups[1]]
                });

            const result = await checkCloudWatchLogGroupRetention.execute("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when API call fails", async () => {
            mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).rejects(
                new Error("API Error")
            );

            const result = await checkCloudWatchLogGroupRetention.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking CloudWatch log groups: API Error");
        });
    });
});