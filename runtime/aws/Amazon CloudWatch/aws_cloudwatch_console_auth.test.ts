// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { CloudWatchClient, DescribeAlarmsForMetricCommand } from "@aws-sdk/client-cloudwatch";
import {
	CloudWatchLogsClient,
	DescribeMetricFiltersCommand
} from "@aws-sdk/client-cloudwatch-logs";
import {
	CloudTrailClient,
	DescribeTrailsCommand,
	GetTrailStatusCommand
} from "@aws-sdk/client-cloudtrail";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkConsoleAuthMonitoring from "./aws_cloudwatch_console_auth";

const mockCloudWatchClient = mockClient(CloudWatchClient);
const mockCloudWatchLogsClient = mockClient(CloudWatchLogsClient);
const mockCloudTrailClient = mockClient(CloudTrailClient);

const REQUIRED_PATTERN =
	'{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }';

describe("checkConsoleAuthMonitoring", () => {
	beforeEach(() => {
		mockCloudWatchClient.reset();
		mockCloudWatchLogsClient.reset();
		mockCloudTrailClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when proper monitoring is configured", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [
					{
						Name: "test-trail",
						TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail",
						CloudWatchLogsLogGroupArn:
							"arn:aws:logs:us-east-1:123456789012:log-group:test-log-group"
					}
				]
			});

			mockCloudTrailClient.on(GetTrailStatusCommand).resolves({
				IsLogging: true
			});

			mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
				metricFilters: [
					{
						filterPattern: REQUIRED_PATTERN,
						metricTransformations: [
							{
								metricName: "ConsoleAuthFailures",
								metricNamespace: "CloudTrail"
							}
						]
					}
				]
			});

			mockCloudWatchClient.on(DescribeAlarmsForMetricCommand).resolves({
				MetricAlarms: [
					{
						AlarmName: "ConsoleAuthFailuresAlarm"
					}
				]
			});

			const result = await checkConsoleAuthMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-log-group");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no CloudTrail trails exist", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: []
			});

			const result = await checkConsoleAuthMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No CloudTrail trails found");
		});

		it("should return FAIL when metric filter is missing", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [
					{
						Name: "test-trail",
						TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail",
						CloudWatchLogsLogGroupArn:
							"arn:aws:logs:us-east-1:123456789012:log-group:test-log-group"
					}
				]
			});

			mockCloudTrailClient.on(GetTrailStatusCommand).resolves({
				IsLogging: true
			});

			mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
				metricFilters: []
			});

			const result = await checkConsoleAuthMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"CloudTrail log group does not have required console authentication failures metric filter"
			);
		});

		it("should return FAIL when no alarm is configured", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [
					{
						Name: "test-trail",
						TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail",
						CloudWatchLogsLogGroupArn:
							"arn:aws:logs:us-east-1:123456789012:log-group:test-log-group"
					}
				]
			});

			mockCloudTrailClient.on(GetTrailStatusCommand).resolves({
				IsLogging: true
			});

			mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
				metricFilters: [
					{
						filterPattern: REQUIRED_PATTERN,
						metricTransformations: [
							{
								metricName: "ConsoleAuthFailures",
								metricNamespace: "CloudTrail"
							}
						]
					}
				]
			});

			mockCloudWatchClient.on(DescribeAlarmsForMetricCommand).resolves({
				MetricAlarms: []
			});

			const result = await checkConsoleAuthMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No alarm configured for console authentication failures metric filter"
			);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API calls fail", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).rejects(new Error("API Error"));

			const result = await checkConsoleAuthMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudWatch configuration");
		});

		it("should handle invalid CloudWatch Logs configuration", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [
					{
						Name: "test-trail",
						TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail",
						CloudWatchLogsLogGroupArn: "invalid-arn" // Invalid ARN format
					}
				]
			});

			mockCloudTrailClient.on(GetTrailStatusCommand).resolves({
				IsLogging: true
			});

			const result = await checkConsoleAuthMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Invalid CloudWatch Logs configuration");
		});
	});
});
