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
import checkSecurityGroupMonitoring from "./aws_cloudwatch_security_group";

const mockCloudWatchClient = mockClient(CloudWatchClient);
const mockCloudWatchLogsClient = mockClient(CloudWatchLogsClient);
const mockCloudTrailClient = mockClient(CloudTrailClient);

const SECURITY_GROUP_PATTERN =
	"{ ($.eventName = AuthorizeSecurityGroupIngress) || " +
	"($.eventName = AuthorizeSecurityGroupEgress) || " +
	"($.eventName = RevokeSecurityGroupIngress) || " +
	"($.eventName = RevokeSecurityGroupEgress) || " +
	"($.eventName = CreateSecurityGroup) || " +
	"($.eventName = DeleteSecurityGroup) }";

describe("checkSecurityGroupMonitoring", () => {
	beforeEach(() => {
		mockCloudWatchClient.reset();
		mockCloudWatchLogsClient.reset();
		mockCloudTrailClient.reset();
	});

	it("should return PASS when monitoring is properly configured", async () => {
		mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
			trailList: [
				{
					Name: "test-trail",
					TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail",
					CloudWatchLogsLogGroupArn: "arn:aws:logs:us-east-1:123456789012:log-group:test-group"
				}
			]
		});

		mockCloudTrailClient.on(GetTrailStatusCommand).resolves({
			IsLogging: true
		});

		mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
			metricFilters: [
				{
					filterPattern: SECURITY_GROUP_PATTERN,
					metricTransformations: [
						{
							metricName: "SecurityGroupChanges",
							metricNamespace: "CloudTrail"
						}
					]
				}
			]
		});

		mockCloudWatchClient.on(DescribeAlarmsForMetricCommand).resolves({
			MetricAlarms: [
				{
					AlarmName: "SecurityGroupChangesAlarm"
				}
			]
		});

		const result = await checkSecurityGroupMonitoring.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		expect(result.checks[0].resourceName).toBe("test-group");
	});

	it("should return FAIL when no CloudTrail trails exist", async () => {
		mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
			trailList: []
		});

		const result = await checkSecurityGroupMonitoring.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		expect(result.checks[0].message).toBe("No CloudTrail trails found");
	});

	it("should return FAIL when no metric filter exists", async () => {
		mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
			trailList: [
				{
					Name: "test-trail",
					TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail",
					CloudWatchLogsLogGroupArn: "arn:aws:logs:us-east-1:123456789012:log-group:test-group"
				}
			]
		});

		mockCloudTrailClient.on(GetTrailStatusCommand).resolves({
			IsLogging: true
		});

		mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
			metricFilters: []
		});

		const result = await checkSecurityGroupMonitoring.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		expect(result.checks[0].message).toBe(
			"CloudTrail log group does not have required security group changes metric filter"
		);
	});

	it("should return FAIL when no alarm is configured", async () => {
		mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
			trailList: [
				{
					Name: "test-trail",
					TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail",
					CloudWatchLogsLogGroupArn: "arn:aws:logs:us-east-1:123456789012:log-group:test-group"
				}
			]
		});

		mockCloudTrailClient.on(GetTrailStatusCommand).resolves({
			IsLogging: true
		});

		mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
			metricFilters: [
				{
					filterPattern: SECURITY_GROUP_PATTERN,
					metricTransformations: [
						{
							metricName: "SecurityGroupChanges",
							metricNamespace: "CloudTrail"
						}
					]
				}
			]
		});

		mockCloudWatchClient.on(DescribeAlarmsForMetricCommand).resolves({
			MetricAlarms: []
		});

		const result = await checkSecurityGroupMonitoring.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		expect(result.checks[0].message).toBe(
			"No alarm configured for security group changes metric filter"
		);
	});

	it("should return ERROR when API calls fail", async () => {
		mockCloudTrailClient.on(DescribeTrailsCommand).rejects(new Error("API Error"));

		const result = await checkSecurityGroupMonitoring.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
		expect(result.checks[0].message).toContain("Error checking security group monitoring");
	});
});
