// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import {
	CloudWatchLogsClient,
	DescribeLogGroupsCommand,
	DescribeMetricFiltersCommand
} from "@aws-sdk/client-cloudwatch-logs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkCmkMonitoringCompliance from "./aws_cloudwatch_cmk";

const mockCloudWatchClient = mockClient(CloudWatchClient);
const mockCloudWatchLogsClient = mockClient(CloudWatchLogsClient);

const REQUIRED_PATTERN =
	"{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion)) }";

describe("checkCmkMonitoringCompliance", () => {
	beforeEach(() => {
		mockCloudWatchClient.reset();
		mockCloudWatchLogsClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when log group has required metric filter and alarm", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
				logGroups: [
					{
						logGroupName: "test-log-group",
						arn: "arn:aws:logs:us-east-1:123456789012:log-group:test-log-group"
					}
				]
			});

			mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
				metricFilters: [
					{
						filterPattern: REQUIRED_PATTERN,
						metricTransformations: [
							{
								metricName: "CMKChanges"
							}
						]
					}
				]
			});

			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: [
					{
						AlarmName: "CMKChangesAlarm"
					}
				]
			});

			const result = await checkCmkMonitoringCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-log-group");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no log groups exist", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
				logGroups: []
			});

			const result = await checkCmkMonitoringCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No CloudWatch Log Groups found");
		});

		it("should return FAIL when metric filter is missing", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
				logGroups: [
					{
						logGroupName: "test-log-group",
						arn: "arn:aws:logs:us-east-1:123456789012:log-group:test-log-group"
					}
				]
			});

			mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
				metricFilters: []
			});

			const result = await checkCmkMonitoringCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("does not have required metric filter");
		});

		it("should return FAIL when alarm is missing", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
				logGroups: [
					{
						logGroupName: "test-log-group",
						arn: "arn:aws:logs:us-east-1:123456789012:log-group:test-log-group"
					}
				]
			});

			mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
				metricFilters: [
					{
						filterPattern: REQUIRED_PATTERN,
						metricTransformations: [
							{
								metricName: "CMKChanges"
							}
						]
					}
				]
			});

			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: []
			});

			const result = await checkCmkMonitoringCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("No alarm configured");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API calls fail", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).rejects(new Error("API Error"));

			const result = await checkCmkMonitoringCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudWatch configuration");
		});

		it("should handle missing or undefined values", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
				logGroups: [
					{
						logGroupName: undefined,
						arn: undefined
					}
				]
			});

			const result = await checkCmkMonitoringCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});
});
