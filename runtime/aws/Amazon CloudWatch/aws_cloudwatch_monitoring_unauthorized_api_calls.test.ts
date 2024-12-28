// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import {
	CloudWatchLogsClient,
	DescribeLogGroupsCommand,
	DescribeMetricFiltersCommand
} from "@aws-sdk/client-cloudwatch-logs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkCloudWatchApiMonitoring from "./aws_cloudwatch_monitoring_unauthorized_api_calls";

const mockCloudWatchClient = mockClient(CloudWatchClient);
const mockCloudWatchLogsClient = mockClient(CloudWatchLogsClient);

const REQUIRED_PATTERN =
	'{ ($.errorCode ="*UnauthorizedOperation") || ($.errorCode ="AccessDenied*") && ($.sourceIPAddress!="delivery.logs.amazonaws.com") && ($.eventName!="HeadBucket") }';

describe("checkCloudWatchApiMonitoring", () => {
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
								metricName: "UnauthorizedAPICalls"
							}
						]
					}
				]
			});

			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: [
					{
						AlarmName: "UnauthorizedAPICallsAlarm"
					}
				]
			});

			const result = await checkCloudWatchApiMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-log-group");
		});

		it("should handle multiple compliant log groups", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
				logGroups: [
					{ logGroupName: "log-group-1", arn: "arn:1" },
					{ logGroupName: "log-group-2", arn: "arn:2" }
				]
			});

			mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
				metricFilters: [
					{
						filterPattern: REQUIRED_PATTERN,
						metricTransformations: [{ metricName: "UnauthorizedAPICalls" }]
					}
				]
			});

			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: [{ AlarmName: "Alarm" }]
			});

			const result = await checkCloudWatchApiMonitoring.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no log groups exist", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
				logGroups: []
			});

			const result = await checkCloudWatchApiMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No CloudWatch Log Groups found");
		});

		it("should return FAIL when metric filter pattern does not match required pattern", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
				logGroups: [{ logGroupName: "test-log-group", arn: "arn:1" }]
			});

			mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
				metricFilters: [
					{
						filterPattern: "wrong-pattern",
						metricTransformations: [{ metricName: "WrongMetric" }]
					}
				]
			});

			const result = await checkCloudWatchApiMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("does not have required metric filter");
		});

		it("should return FAIL when no alarm is configured for metric filter", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
				logGroups: [{ logGroupName: "test-log-group", arn: "arn:1" }]
			});

			mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
				metricFilters: [
					{
						filterPattern: REQUIRED_PATTERN,
						metricTransformations: [{ metricName: "UnauthorizedAPICalls" }]
					}
				]
			});

			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: []
			});

			const result = await checkCloudWatchApiMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("No alarm configured");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API calls fail", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).rejects(new Error("API Error"));

			const result = await checkCloudWatchApiMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudWatch configuration");
		});
	});
});
