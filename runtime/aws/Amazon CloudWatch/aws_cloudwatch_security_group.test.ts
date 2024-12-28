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
import checkSecurityGroupMonitoring from "./aws_cloudwatch_security_group";

const mockCloudWatchClient = mockClient(CloudWatchClient);
const mockCloudWatchLogsClient = mockClient(CloudWatchLogsClient);

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
	});

	it("should return PASS when monitoring is properly configured", async () => {
		mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
			logGroups: [
				{
					logGroupName: "test-group",
					arn: "arn:aws:logs:us-east-1:123456789012:log-group:test-group"
				}
			]
		});

		mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
			metricFilters: [
				{
					filterPattern: SECURITY_GROUP_PATTERN,
					metricTransformations: [
						{
							metricName: "SecurityGroupChanges"
						}
					]
				}
			]
		});

		mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
			MetricAlarms: [
				{
					AlarmName: "SecurityGroupChangesAlarm"
				}
			]
		});

		const result = await checkSecurityGroupMonitoring.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
	});

	it("should return FAIL when no log groups exist", async () => {
		mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
			logGroups: []
		});

		const result = await checkSecurityGroupMonitoring.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		expect(result.checks[0].message).toBe("No CloudWatch Log Groups found");
	});

	it("should return FAIL when no metric filter exists", async () => {
		mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
			logGroups: [
				{
					logGroupName: "test-group",
					arn: "arn:aws:logs:us-east-1:123456789012:log-group:test-group"
				}
			]
		});

		mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
			metricFilters: []
		});

		const result = await checkSecurityGroupMonitoring.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		expect(result.checks[0].message).toContain(
			"Log group does not have required security group changes metric filter"
		);
	});

	it("should return FAIL when no alarm is configured", async () => {
		mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
			logGroups: [
				{
					logGroupName: "test-group",
					arn: "arn:aws:logs:us-east-1:123456789012:log-group:test-group"
				}
			]
		});

		mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
			metricFilters: [
				{
					filterPattern: SECURITY_GROUP_PATTERN,
					metricTransformations: [
						{
							metricName: "SecurityGroupChanges"
						}
					]
				}
			]
		});

		mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
			MetricAlarms: []
		});

		const result = await checkSecurityGroupMonitoring.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		expect(result.checks[0].message).toContain("No alarm configured");
	});

	it("should return ERROR when API calls fail", async () => {
		mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).rejects(new Error("API Error"));

		const result = await checkSecurityGroupMonitoring.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
		expect(result.checks[0].message).toContain("Error checking");
	});
});
