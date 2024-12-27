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
import checkS3PolicyMonitoring from "./aws_cloudwatch_s3_policy_change";

const mockCloudWatchClient = mockClient(CloudWatchClient);
const mockCloudWatchLogsClient = mockClient(CloudWatchLogsClient);

const REQUIRED_PATTERN =
	"{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }";

describe("checkS3PolicyMonitoring", () => {
	beforeEach(() => {
		mockCloudWatchClient.reset();
		mockCloudWatchLogsClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when proper monitoring is configured", async () => {
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
								metricName: "s3-policy-changes"
							}
						]
					}
				]
			});

			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: [
					{
						AlarmName: "S3PolicyChangeAlarm",
						MetricName: "s3-policy-changes"
					}
				]
			});

			const result = await checkS3PolicyMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-log-group");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no log groups exist", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
				logGroups: []
			});

			const result = await checkS3PolicyMonitoring.execute("us-east-1");
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

			const result = await checkS3PolicyMonitoring.execute("us-east-1");
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
								metricName: "s3-policy-changes"
							}
						]
					}
				]
			});

			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: []
			});

			const result = await checkS3PolicyMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("No alarms configured");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API calls fail", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).rejects(new Error("API Error"));

			const result = await checkS3PolicyMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudWatch configuration");
		});

		it("should handle missing log group names", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
				logGroups: [{ arn: "test-arn" }] // Missing logGroupName
			});

			const result = await checkS3PolicyMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("No monitoring configuration found");
		});
	});
});
