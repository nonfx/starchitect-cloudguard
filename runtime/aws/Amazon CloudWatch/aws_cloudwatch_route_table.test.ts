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
import checkRouteTableMonitoring from "./aws_cloudwatch_route_table";

const mockCloudWatchClient = mockClient(CloudWatchClient);
const mockCloudWatchLogsClient = mockClient(CloudWatchLogsClient);
const mockCloudTrailClient = mockClient(CloudTrailClient);

const mockLogGroup = {
	logGroupName: "test-log-group",
	arn: "arn:aws:logs:us-east-1:123456789012:log-group:test-log-group"
};

const mockMetricFilter = {
	filterPattern:
		"{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }",
	metricTransformations: [{ metricName: "RouteTableChanges" }]
};

describe("checkRouteTableMonitoring", () => {
	beforeEach(() => {
		mockCloudWatchClient.reset();
		mockCloudWatchLogsClient.reset();
		mockCloudTrailClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when log group has proper metric filter and alarm", async () => {
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

			mockCloudWatchLogsClient
				.on(DescribeMetricFiltersCommand)
				.resolves({ metricFilters: [mockMetricFilter] });

			mockCloudWatchClient.on(DescribeAlarmsForMetricCommand).resolves({
				MetricAlarms: [{ AlarmName: "RouteTableChangesAlarm" }]
			});

			const result = await checkRouteTableMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-log-group");
		});

		it("should handle multiple compliant log groups", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [
					{
						Name: "test-trail-1",
						TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail-1",
						CloudWatchLogsLogGroupArn: "arn:aws:logs:us-east-1:123456789012:log-group:log-group-1"
					},
					{
						Name: "test-trail-2",
						TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail-2",
						CloudWatchLogsLogGroupArn: "arn:aws:logs:us-east-1:123456789012:log-group:log-group-2"
					}
				]
			});

			mockCloudTrailClient.on(GetTrailStatusCommand).resolves({
				IsLogging: true
			});

			mockCloudWatchLogsClient
				.on(DescribeMetricFiltersCommand)
				.resolves({ metricFilters: [mockMetricFilter] });

			mockCloudWatchClient.on(DescribeAlarmsForMetricCommand).resolves({
				MetricAlarms: [{ AlarmName: "RouteTableChangesAlarm" }]
			});

			const result = await checkRouteTableMonitoring.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no CloudTrail trails exist", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: []
			});

			const result = await checkRouteTableMonitoring.execute("us-east-1");
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

			const result = await checkRouteTableMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain(
				"does not have required route table monitoring metric filter"
			);
		});

		it("should return FAIL when alarm is missing", async () => {
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

			mockCloudWatchLogsClient
				.on(DescribeMetricFiltersCommand)
				.resolves({ metricFilters: [mockMetricFilter] });

			mockCloudWatchClient.on(DescribeAlarmsForMetricCommand).resolves({
				MetricAlarms: []
			});

			const result = await checkRouteTableMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No alarms configured for route table monitoring metric"
			);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API calls fail", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).rejects(new Error("API Error"));

			const result = await checkRouteTableMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking route table monitoring");
		});

		it("should handle metric filter API errors", async () => {
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

			mockCloudWatchLogsClient
				.on(DescribeMetricFiltersCommand)
				.rejects(new Error("Metric Filter API Error"));

			const result = await checkRouteTableMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
		});
	});
});
