import {
	CloudWatchLogsClient,
	DescribeLogGroupsCommand,
	DescribeMetricFiltersCommand
} from "@aws-sdk/client-cloudwatch-logs";
import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkCloudTrailConfigurationMonitoring from "./aws_cloudwatch_cloudtrail";

const mockCloudWatchLogsClient = mockClient(CloudWatchLogsClient);
const mockCloudWatchClient = mockClient(CloudWatchClient);

const REQUIRED_PATTERN =
	"{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }";

describe("checkCloudTrailConfigurationMonitoring", () => {
	beforeEach(() => {
		mockCloudWatchLogsClient.reset();
		mockCloudWatchClient.reset();
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
								metricName: "CloudTrailChangeCount"
							}
						]
					}
				]
			});

			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: [
					{
						AlarmName: "CloudTrailChangeAlarm"
					}
				]
			});

			const result = await checkCloudTrailConfigurationMonitoring.execute();
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
						metricTransformations: [{ metricName: "CloudTrailChangeCount" }]
					}
				]
			});

			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: [{ AlarmName: "CloudTrailChangeAlarm" }]
			});

			const result = await checkCloudTrailConfigurationMonitoring.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no log groups exist", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({ logGroups: [] });

			const result = await checkCloudTrailConfigurationMonitoring.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No CloudWatch Log Groups found");
		});

		it("should return FAIL when metric filter is missing", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
				logGroups: [{ logGroupName: "test-group", arn: "arn:test" }]
			});

			mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
				metricFilters: [
					{
						filterPattern: "different-pattern",
						metricTransformations: [{ metricName: "OtherMetric" }]
					}
				]
			});

			const result = await checkCloudTrailConfigurationMonitoring.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("does not have required metric filter");
		});

		it("should return FAIL when alarm is missing", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
				logGroups: [{ logGroupName: "test-group", arn: "arn:test" }]
			});

			mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
				metricFilters: [
					{
						filterPattern: REQUIRED_PATTERN,
						metricTransformations: [{ metricName: "CloudTrailChangeCount" }]
					}
				]
			});

			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({ MetricAlarms: [] });

			const result = await checkCloudTrailConfigurationMonitoring.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("No alarm configured");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API calls fail", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).rejects(new Error("API Error"));

			const result = await checkCloudTrailConfigurationMonitoring.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudWatch configuration");
		});

		it("should handle metric filter API errors", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
				logGroups: [{ logGroupName: "test-group", arn: "arn:test" }]
			});

			mockCloudWatchLogsClient
				.on(DescribeMetricFiltersCommand)
				.rejects(new Error("Metric Filter API Error"));

			const result = await checkCloudTrailConfigurationMonitoring.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
		});
	});
});
