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
import checkVpcChangesMonitored from "./aws_cloudwatch_vpc_changes_monitored";

const mockCloudWatchClient = mockClient(CloudWatchClient);
const mockCloudWatchLogsClient = mockClient(CloudWatchLogsClient);
const mockCloudTrailClient = mockClient(CloudTrailClient);

const REQUIRED_PATTERN =
	"{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }";

describe("checkVpcChangesMonitored", () => {
	beforeEach(() => {
		mockCloudWatchClient.reset();
		mockCloudWatchLogsClient.reset();
		mockCloudTrailClient.reset();
	});

	it("should return PASS when log group has correct metric filter and alarm", async () => {
		mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
			trailList: [
				{
					Name: "test-trail",
					TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail",
					CloudWatchLogsLogGroupArn: "arn:aws:logs:us-east-1:123456789012:log-group:test-log-group"
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
							metricName: "VpcChanges",
							metricNamespace: "CloudTrail"
						}
					]
				}
			]
		});

		mockCloudWatchClient.on(DescribeAlarmsForMetricCommand).resolves({
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

	it("should return FAIL when no CloudTrail trails exist", async () => {
		mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
			trailList: []
		});

		const result = await checkVpcChangesMonitored.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		expect(result.checks[0].message).toBe("No CloudTrail trails found");
	});

	it("should return FAIL when metric filter is missing", async () => {
		mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
			trailList: [
				{
					Name: "test-trail",
					TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail",
					CloudWatchLogsLogGroupArn: "arn:aws:logs:us-east-1:123456789012:log-group:test-log-group"
				}
			]
		});

		mockCloudTrailClient.on(GetTrailStatusCommand).resolves({
			IsLogging: true
		});

		mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
			metricFilters: []
		});

		const result = await checkVpcChangesMonitored.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		expect(result.checks[0].message).toBe(
			"CloudTrail log group does not have required VPC changes metric filter"
		);
	});

	it("should return FAIL when no alarm is configured", async () => {
		mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
			trailList: [
				{
					Name: "test-trail",
					TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail",
					CloudWatchLogsLogGroupArn: "arn:aws:logs:us-east-1:123456789012:log-group:test-log-group"
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
							metricName: "VpcChanges",
							metricNamespace: "CloudTrail"
						}
					]
				}
			]
		});

		mockCloudWatchClient.on(DescribeAlarmsForMetricCommand).resolves({
			MetricAlarms: []
		});

		const result = await checkVpcChangesMonitored.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		expect(result.checks[0].message).toBe("No alarm configured for VPC changes metric filter");
	});

	it("should return ERROR when API calls fail", async () => {
		mockCloudTrailClient.on(DescribeTrailsCommand).rejects(new Error("API Error"));

		const result = await checkVpcChangesMonitored.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
		expect(result.checks[0].message).toContain("Error checking VPC monitoring");
	});
});
