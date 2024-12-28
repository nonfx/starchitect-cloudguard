// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { CloudWatchClient, GetMetricDataCommand } from "@aws-sdk/client-cloudwatch";
import {
	CloudWatchLogsClient,
	DescribeLogGroupsCommand,
	DescribeMetricFiltersCommand
} from "@aws-sdk/client-cloudwatch-logs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkCloudWatchOrgChangesMonitored from "./aws_cloudwatch_org_changes_monitored";

const mockCloudWatchClient = mockClient(CloudWatchClient);
const mockCloudWatchLogsClient = mockClient(CloudWatchLogsClient);

const REQUIRED_PATTERN =
	'{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = "AcceptHandshake") || ($.eventName = "AttachPolicy") || ($.eventName = "CreateAccount") || ($.eventName = "CreateOrganizationalUnit") || ($.eventName = "CreatePolicy") || ($.eventName = "DeclineHandshake") || ($.eventName = "DeleteOrganization") || ($.eventName = "DeleteOrganizationalUnit") || ($.eventName = "DeletePolicy") || ($.eventName = "DetachPolicy") || ($.eventName = "DisablePolicyType") || ($.eventName = "EnablePolicyType") || ($.eventName = "InviteAccountToOrganization") || ($.eventName = "LeaveOrganization") || ($.eventName = "MoveAccount") || ($.eventName = "RemoveAccountFromOrganization") || ($.eventName = "UpdatePolicy") || ($.eventName = "UpdateOrganizationalUnit")) }';

describe("checkCloudWatchOrgChangesMonitored", () => {
	beforeEach(() => {
		mockCloudWatchClient.reset();
		mockCloudWatchLogsClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when log group has correct metric filter and active monitoring", async () => {
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
								metricName: "OrgChangesMetric",
								metricNamespace: "CloudTrail"
							}
						]
					}
				]
			});

			mockCloudWatchClient.on(GetMetricDataCommand).resolves({
				MetricDataResults: [
					{
						Values: [1.0]
					}
				]
			});

			const result = await checkCloudWatchOrgChangesMonitored.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-log-group");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no log groups exist", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({
				logGroups: []
			});

			const result = await checkCloudWatchOrgChangesMonitored.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No CloudWatch Log Groups found");
		});

		it("should return FAIL when metric filter pattern does not match required pattern", async () => {
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
			expect(result.checks[0].message).toContain("does not have required metric filter");
		});

		it("should return FAIL when metric filter has no metric transformations", async () => {
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
						metricTransformations: []
					}
				]
			});

			const result = await checkCloudWatchOrgChangesMonitored.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Metric filter does not have a metric transformation");
		});

		it("should return FAIL when no metric data is found", async () => {
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
								metricName: "OrgChangesMetric",
								metricNamespace: "CloudTrail"
							}
						]
					}
				]
			});

			mockCloudWatchClient.on(GetMetricDataCommand).resolves({
				MetricDataResults: [
					{
						Values: []
					}
				]
			});

			const result = await checkCloudWatchOrgChangesMonitored.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("No metric data found");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API calls fail", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).rejects(new Error("API Error"));

			const result = await checkCloudWatchOrgChangesMonitored.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudWatch configuration");
		});
	});
});
