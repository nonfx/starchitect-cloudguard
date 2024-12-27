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
import checkVpcChangesMonitored from "./aws_cloudwatch_vpc_changes_monitored";

const mockCloudWatchClient = mockClient(CloudWatchClient);
const mockCloudWatchLogsClient = mockClient(CloudWatchLogsClient);

const REQUIRED_PATTERN =
	"{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }";

describe("checkVpcChangesMonitored", () => {
	beforeEach(() => {
		mockCloudWatchClient.reset();
		mockCloudWatchLogsClient.reset();
	});

	it("should return PASS when log group has correct metric filter and alarm", async () => {
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
							metricName: "VpcChanges",
							metricNamespace: "CloudTrail"
						}
					]
				}
			]
		});

		mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
			MetricAlarms: [
				{
					AlarmName: "VpcChangesAlarm"
				}
			]
		});

		const result = await checkVpcChangesMonitored.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		expect(result.checks[0].resourceName).toBe("test-log-group");
	});

	it("should return FAIL when no log groups exist", async () => {
		mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
			logGroups: []
		});

		const result = await checkVpcChangesMonitored.execute("us-east-1");
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

		const result = await checkVpcChangesMonitored.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		expect(result.checks[0].message).toContain("does not have required VPC changes metric filter");
	});

	it("should return FAIL when no alarm is configured", async () => {
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
							metricName: "VpcChanges",
							metricNamespace: "CloudTrail"
						}
					]
				}
			]
		});

		mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
			MetricAlarms: []
		});

		const result = await checkVpcChangesMonitored.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		expect(result.checks[0].message).toContain("No alarm configured");
	});

	it("should return ERROR when API calls fail", async () => {
		mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).rejects(new Error("API Error"));

		const result = await checkVpcChangesMonitored.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
		expect(result.checks[0].message).toContain("Error checking VPC monitoring");
	});
});
