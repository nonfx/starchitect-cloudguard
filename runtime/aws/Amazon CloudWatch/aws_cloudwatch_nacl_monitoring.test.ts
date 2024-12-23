import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import {
    CloudWatchLogsClient,
    DescribeLogGroupsCommand,
    DescribeMetricFiltersCommand
} from "@aws-sdk/client-cloudwatch-logs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "@codegen/utils/stringUtils";
import checkNaclMonitoringCompliance from "./aws_cloudwatch_nacl_monitoring";

const mockCloudWatchClient = mockClient(CloudWatchClient);
const mockCloudWatchLogsClient = mockClient(CloudWatchLogsClient);

const mockLogGroup = {
    logGroupName: "test-log-group",
    arn: "arn:aws:logs:us-east-1:123456789012:log-group:test-log-group"
};

const mockMetricFilter = {
    filterPattern: '{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }',
    metricTransformations: [
        {
            metricName: "NACLChanges",
            metricNamespace: "CloudTrailMetrics"
        }
    ]
};

describe("checkNaclMonitoringCompliance", () => {
    beforeEach(() => {
        mockCloudWatchClient.reset();
        mockCloudWatchLogsClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when log group has required metric filter and alarm", async () => {
            mockCloudWatchLogsClient
                .on(DescribeLogGroupsCommand)
                .resolves({ logGroups: [mockLogGroup] });
            
            mockCloudWatchLogsClient
                .on(DescribeMetricFiltersCommand)
                .resolves({ metricFilters: [mockMetricFilter] });
            
            mockCloudWatchClient
                .on(DescribeAlarmsCommand)
                .resolves({ 
                    MetricAlarms: [{
                        AlarmName: "NACLChangesAlarm",
                        MetricName: "NACLChanges"
                    }]
                });

            const result = await checkNaclMonitoringCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe(mockLogGroup.logGroupName);
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when no log groups exist", async () => {
            mockCloudWatchLogsClient
                .on(DescribeLogGroupsCommand)
                .resolves({ logGroups: [] });

            const result = await checkNaclMonitoringCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("No CloudWatch Log Groups found");
        });

        it("should return FAIL when metric filter is missing", async () => {
            mockCloudWatchLogsClient
                .on(DescribeLogGroupsCommand)
                .resolves({ logGroups: [mockLogGroup] });
            
            mockCloudWatchLogsClient
                .on(DescribeMetricFiltersCommand)
                .resolves({ metricFilters: [] });

            const result = await checkNaclMonitoringCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain("does not have required NACL changes metric filter");
        });

        it("should return FAIL when alarm is missing", async () => {
            mockCloudWatchLogsClient
                .on(DescribeLogGroupsCommand)
                .resolves({ logGroups: [mockLogGroup] });
            
            mockCloudWatchLogsClient
                .on(DescribeMetricFiltersCommand)
                .resolves({ metricFilters: [mockMetricFilter] });
            
            mockCloudWatchClient
                .on(DescribeAlarmsCommand)
                .resolves({ MetricAlarms: [] });

            const result = await checkNaclMonitoringCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain("No alarms configured");
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when CloudWatch API call fails", async () => {
            mockCloudWatchLogsClient
                .on(DescribeLogGroupsCommand)
                .rejects(new Error("API Error"));

            const result = await checkNaclMonitoringCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking CloudWatch configuration");
        });

        it("should return ERROR when metric filter API call fails", async () => {
            mockCloudWatchLogsClient
                .on(DescribeLogGroupsCommand)
                .resolves({ logGroups: [mockLogGroup] });
            
            mockCloudWatchLogsClient
                .on(DescribeMetricFiltersCommand)
                .rejects(new Error("API Error"));

            const result = await checkNaclMonitoringCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
        });
    });
});