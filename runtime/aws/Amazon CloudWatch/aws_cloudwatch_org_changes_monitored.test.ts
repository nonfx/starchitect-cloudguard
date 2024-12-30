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
import checkCloudWatchOrgChangesMonitored from "./aws_cloudwatch_org_changes_monitored";

const mockCloudWatchClient = mockClient(CloudWatchClient);
const mockCloudWatchLogsClient = mockClient(CloudWatchLogsClient);
const mockCloudTrailClient = mockClient(CloudTrailClient);

const REQUIRED_PATTERN =
	'{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = "AcceptHandshake") || ($.eventName = "AttachPolicy") || ($.eventName = "CreateAccount") || ($.eventName = "CreateOrganizationalUnit") || ($.eventName = "CreatePolicy") || ($.eventName = "DeclineHandshake") || ($.eventName = "DeleteOrganization") || ($.eventName = "DeleteOrganizationalUnit") || ($.eventName = "DeletePolicy") || ($.eventName = "DetachPolicy") || ($.eventName = "DisablePolicyType") || ($.eventName = "EnablePolicyType") || ($.eventName = "InviteAccountToOrganization") || ($.eventName = "LeaveOrganization") || ($.eventName = "MoveAccount") || ($.eventName = "RemoveAccountFromOrganization") || ($.eventName = "UpdatePolicy") || ($.eventName = "UpdateOrganizationalUnit")) }';

describe("checkCloudWatchOrgChangesMonitored", () => {
	beforeEach(() => {
		mockCloudWatchClient.reset();
		mockCloudWatchLogsClient.reset();
		mockCloudTrailClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when log group has correct metric filter and active monitoring", async () => {
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
								metricName: "OrgChangesMetric",
								metricNamespace: "CloudTrail"
							}
						]
					}
				]
			});

			mockCloudWatchClient.on(DescribeAlarmsForMetricCommand).resolves({
				MetricAlarms: [
					{
						AlarmName: "test-alarm"
					}
				]
			});

			const result = await checkCloudWatchOrgChangesMonitored.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-log-group");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no CloudTrail trails exist", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: []
			});

			const result = await checkCloudWatchOrgChangesMonitored.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No CloudTrail trails found");
		});

		it("should return FAIL when metric filter pattern does not match required pattern", async () => {
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
						filterPattern: "wrong-pattern",
						metricTransformations: [
							{
								metricName: "OrgChangesMetric",
								metricNamespace: "CloudTrail"
							}
						]
					}
				]
			});

			const result = await checkCloudWatchOrgChangesMonitored.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"CloudTrail log group does not have required Organizations changes metric filter"
			);
		});

		it("should return FAIL when metric filter has no metric transformations", async () => {
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
						metricTransformations: []
					}
				]
			});

			const result = await checkCloudWatchOrgChangesMonitored.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Metric filter does not have a valid metric transformation"
			);
		});

		it("should return FAIL when no alarms are configured", async () => {
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
								metricName: "OrgChangesMetric",
								metricNamespace: "CloudTrail"
							}
						]
					}
				]
			});

			mockCloudWatchClient.on(DescribeAlarmsForMetricCommand).resolves({
				MetricAlarms: []
			});

			const result = await checkCloudWatchOrgChangesMonitored.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No alarm configured for Organizations changes metric filter"
			);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API calls fail", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).rejects(new Error("API Error"));

			const result = await checkCloudWatchOrgChangesMonitored.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudWatch configuration");
		});
	});

	describe("Metadata", () => {
		it("should include correct metadata in results", async () => {
			expect(checkCloudWatchOrgChangesMonitored.title).toBe(
				"Ensure AWS Organizations changes are monitored"
			);
			expect(checkCloudWatchOrgChangesMonitored.controls).toHaveLength(1);
			expect(checkCloudWatchOrgChangesMonitored.controls[0].id).toBe(
				"CIS-AWS-Foundations-Benchmark_v3.0.0_4.15"
			);
		});
	});
});
