// @ts-nocheck
import { CloudWatchLogsClient, DescribeMetricFiltersCommand } from "@aws-sdk/client-cloudwatch-logs";
import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkVpcNetworkChanges from "./check-vpc-network-changes";

const mockCloudWatchLogsClient = mockClient(CloudWatchLogsClient);
const mockCloudWatchClient = mockClient(CloudWatchClient);

const validFilterPattern = '{ $.eventName = CreateVpc || $.eventName = DeleteVpc || $.eventName = ModifyVpcAttribute || $.eventName = AcceptVpcPeeringConnection || $.eventName = CreateVpcPeeringConnection || $.eventName = DeleteVpcPeeringConnection || $.eventName = RejectVpcPeeringConnection || $.eventName = AttachClassicLinkVpc || $.eventName = DetachClassicLinkVpc || $.eventName = DisableVpcClassicLink || $.eventName = EnableVpcClassicLink }';

describe("checkVpcNetworkChanges", () => {
    beforeEach(() => {
        mockCloudWatchLogsClient.reset();
        mockCloudWatchClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when valid metric filter and alarm exist", async () => {
            mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
                metricFilters: [{
                    filterPattern: validFilterPattern,
                    metricTransformations: [{
                        metricName: "VpcNetworkChanges"
                    }]
                }]
            });

            mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
                MetricAlarms: [{
                    MetricName: "VpcNetworkChanges",
                    AlarmActions: ["arn:aws:sns:us-east-1:123456789012:AlertTopic"]
                }]
            });

            const result = await checkVpcNetworkChanges.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].message).toBe("Valid metric filter and alarm exist for VPC network changes");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when metric filter is missing", async () => {
            mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
                metricFilters: []
            });

            const result = await checkVpcNetworkChanges.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("No valid metric filter found for monitoring VPC network changes");
        });

        it("should return FAIL when alarm is missing", async () => {
            mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
                metricFilters: [{
                    filterPattern: validFilterPattern,
                    metricTransformations: [{
                        metricName: "VpcNetworkChanges"
                    }]
                }]
            });

            mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
                MetricAlarms: []
            });

            const result = await checkVpcNetworkChanges.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("No valid alarm configured for VPC network changes metric");
        });

        it("should return FAIL when alarm has no actions", async () => {
            mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
                metricFilters: [{
                    filterPattern: validFilterPattern,
                    metricTransformations: [{
                        metricName: "VpcNetworkChanges"
                    }]
                }]
            });

            mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
                MetricAlarms: [{
                    MetricName: "VpcNetworkChanges",
                    AlarmActions: []
                }]
            });

            const result = await checkVpcNetworkChanges.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when CloudWatch Logs API call fails", async () => {
            mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).rejects(
                new Error("CloudWatch Logs API error")
            );

            const result = await checkVpcNetworkChanges.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("CloudWatch Logs API error");
        });

        it("should return ERROR when CloudWatch API call fails", async () => {
            mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
                metricFilters: [{
                    filterPattern: validFilterPattern,
                    metricTransformations: [{
                        metricName: "VpcNetworkChanges"
                    }]
                }]
            });

            mockCloudWatchClient.on(DescribeAlarmsCommand).rejects(
                new Error("CloudWatch API error")
            );

            const result = await checkVpcNetworkChanges.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("CloudWatch API error");
        });
    });
});