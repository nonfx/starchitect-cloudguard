import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import {
	CloudWatchLogsClient,
	DescribeLogGroupsCommand,
	DescribeMetricFiltersCommand
} from "@aws-sdk/client-cloudwatch-logs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkMfaMonitoringCompliance from "./aws_cloudwatch_monitoring_signin_mfa";

const mockCloudWatchClient = mockClient(CloudWatchClient);
const mockCloudWatchLogsClient = mockClient(CloudWatchLogsClient);

const mockLogGroup = {
	logGroupName: "test-log-group",
	arn: "arn:aws:logs:us-east-1:123456789012:log-group:test-log-group"
};

const mockMetricFilter = {
	filterPattern: '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }',
	metricTransformations: [
		{
			metricName: "NoMFAConsoleLoginCount"
		}
	]
};

describe("checkMfaMonitoringCompliance", () => {
	beforeEach(() => {
		mockCloudWatchClient.reset();
		mockCloudWatchLogsClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when log group has correct metric filter and alarm", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({ logGroups: [mockLogGroup] });

			mockCloudWatchLogsClient
				.on(DescribeMetricFiltersCommand)
				.resolves({ metricFilters: [mockMetricFilter] });

			mockCloudWatchClient
				.on(DescribeAlarmsCommand)
				.resolves({ MetricAlarms: [{ AlarmName: "test-alarm" }] });

			const result = await checkMfaMonitoringCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-log-group");
		});

		it("should handle multiple compliant log groups", async () => {
			const multipleLogGroups = [
				{ ...mockLogGroup, logGroupName: "log-group-1" },
				{ ...mockLogGroup, logGroupName: "log-group-2" }
			];

			mockCloudWatchLogsClient
				.on(DescribeLogGroupsCommand)
				.resolves({ logGroups: multipleLogGroups });

			mockCloudWatchLogsClient
				.on(DescribeMetricFiltersCommand)
				.resolves({ metricFilters: [mockMetricFilter] });

			mockCloudWatchClient
				.on(DescribeAlarmsCommand)
				.resolves({ MetricAlarms: [{ AlarmName: "test-alarm" }] });

			const result = await checkMfaMonitoringCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no log groups exist", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({ logGroups: [] });

			const result = await checkMfaMonitoringCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No CloudWatch Log Groups found");
		});

		it("should return FAIL when metric filter is missing", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({ logGroups: [mockLogGroup] });

			mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({ metricFilters: [] });

			const result = await checkMfaMonitoringCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("does not have required metric filter");
		});

		it("should return FAIL when alarm is missing", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({ logGroups: [mockLogGroup] });

			mockCloudWatchLogsClient
				.on(DescribeMetricFiltersCommand)
				.resolves({ metricFilters: [mockMetricFilter] });

			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({ MetricAlarms: [] });

			const result = await checkMfaMonitoringCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("No alarm configured");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API calls fail", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).rejects(new Error("API Error"));

			const result = await checkMfaMonitoringCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking MFA monitoring");
		});

		it("should handle metric filter API errors", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({ logGroups: [mockLogGroup] });

			mockCloudWatchLogsClient
				.on(DescribeMetricFiltersCommand)
				.rejects(new Error("Metric Filter API Error"));

			const result = await checkMfaMonitoringCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
		});

		it("should handle alarm API errors", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({ logGroups: [mockLogGroup] });

			mockCloudWatchLogsClient
				.on(DescribeMetricFiltersCommand)
				.resolves({ metricFilters: [mockMetricFilter] });

			mockCloudWatchClient.on(DescribeAlarmsCommand).rejects(new Error("Alarm API Error"));

			const result = await checkMfaMonitoringCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
		});
	});
});
