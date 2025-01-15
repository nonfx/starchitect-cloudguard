// @ts-nocheck
import { CloudWatchClient, GetMetricDataCommand } from "@aws-sdk/client-cloudwatch";
import { 
    CloudWatchLogsClient, 
    DescribeLogGroupsCommand, 
    DescribeMetricFiltersCommand 
} from "@aws-sdk/client-cloudwatch-logs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkLogMetricRoleChanges from "./check-log-metric-role-changes";

const mockCloudWatchClient = mockClient(CloudWatchClient);
const mockCloudWatchLogsClient = mockClient(CloudWatchLogsClient);

const mockLogGroups = [
    {
        logGroupName: "test-log-group-1",
        arn: "arn:aws:logs:us-east-1:123456789012:log-group:test-log-group-1"
    },
    {
        logGroupName: "test-log-group-2",
        arn: "arn:aws:logs:us-east-1:123456789012:log-group:test-log-group-2"
    }
];

const validMetricFilter = {
    filterPattern: "$.eventName = CreateRole || $.eventName = DeleteRole || $.eventName = UpdateRole",
    metricTransformations: [{
        metricName: "RoleChanges",
        metricNamespace: "CloudWatchMetrics"
    }]
};

describe("checkLogMetricRoleChanges", () => {
    beforeEach(() => {
        mockCloudWatchClient.reset();
        mockCloudWatchLogsClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when valid metric filter and alerts exist", async () => {
            mockCloudWatchLogsClient
                .on(DescribeLogGroupsCommand)
                .resolves({ logGroups: [mockLogGroups[0]] })
                .on(DescribeMetricFiltersCommand)
                .resolves({ metricFilters: [validMetricFilter] });

            mockCloudWatchClient
                .on(GetMetricDataCommand)
                .resolves({ 
                    MetricDataResults: [{ Values: [1.0] }] 
                });

            const result = await checkLogMetricRoleChanges.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe(mockLogGroups[0].logGroupName);
        });

        it("should return NOTAPPLICABLE when no log groups exist", async () => {
            mockCloudWatchLogsClient
                .on(DescribeLogGroupsCommand)
                .resolves({ logGroups: [] });

            const result = await checkLogMetricRoleChanges.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No log groups found");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when metric filter exists but no alerts configured", async () => {
            mockCloudWatchLogsClient
                .on(DescribeLogGroupsCommand)
                .resolves({ logGroups: [mockLogGroups[0]] })
                .on(DescribeMetricFiltersCommand)
                .resolves({ metricFilters: [validMetricFilter] });

            mockCloudWatchClient
                .on(GetMetricDataCommand)
                .resolves({ 
                    MetricDataResults: [{ Values: [] }] 
                });

            const result = await checkLogMetricRoleChanges.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("Metric filter exists but no alerts are configured");
        });

        it("should return FAIL when no metric filter is configured", async () => {
            mockCloudWatchLogsClient
                .on(DescribeLogGroupsCommand)
                .resolves({ logGroups: [mockLogGroups[0]] })
                .on(DescribeMetricFiltersCommand)
                .resolves({ metricFilters: [] });

            const result = await checkLogMetricRoleChanges.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("No metric filter configured for IAM role changes");
        });

        it("should handle multiple log groups with mixed compliance", async () => {
            mockCloudWatchLogsClient
                .on(DescribeLogGroupsCommand)
                .resolves({ logGroups: mockLogGroups })
                .on(DescribeMetricFiltersCommand)
                .resolves({ metricFilters: [] })
                .on(DescribeMetricFiltersCommand, { logGroupName: mockLogGroups[1].logGroupName })
                .resolves({ metricFilters: [validMetricFilter] });

            mockCloudWatchClient
                .on(GetMetricDataCommand)
                .resolves({ 
                    MetricDataResults: [{ Values: [1.0] }] 
                });

            const result = await checkLogMetricRoleChanges.execute("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when API calls fail", async () => {
            mockCloudWatchLogsClient
                .on(DescribeLogGroupsCommand)
                .rejects(new Error("API Error"));

            const result = await checkLogMetricRoleChanges.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking metric filters");
        });

        it("should handle missing logGroupName", async () => {
            mockCloudWatchLogsClient
                .on(DescribeLogGroupsCommand)
                .resolves({ logGroups: [{ arn: "test-arn" }] });

            const result = await checkLogMetricRoleChanges.execute("us-east-1");
            expect(result.checks).toHaveLength(0);
        });
    });
});