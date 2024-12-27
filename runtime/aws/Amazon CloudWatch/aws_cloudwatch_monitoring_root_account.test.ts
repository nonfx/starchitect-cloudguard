// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import {
	CloudWatchLogsClient,
	DescribeLogGroupsCommand,
	DescribeMetricFiltersCommand
} from "@aws-sdk/client-cloudwatch-logs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types";
import checkRootAccountMonitoring from "./aws_cloudwatch_monitoring_root_account";

const mockCloudWatchClient = mockClient(CloudWatchClient);
const mockCloudWatchLogsClient = mockClient(CloudWatchLogsClient);

const mockLogGroup = {
	logGroupName: "test-log-group",
	arn: "arn:aws:logs:us-east-1:123456789012:log-group:test-log-group"
};

const mockMetricFilter = {
	filterPattern:
		'{ ($.userIdentity.type = "Root") && ($.userIdentity.invokedBy NOT EXISTS) && ($.eventType != "AwsServiceEvent") }',
	metricTransformations: [{ metricName: "RootAccountUsage" }]
};

describe("checkRootAccountMonitoring", () => {
	beforeEach(() => {
		mockCloudWatchClient.reset();
		mockCloudWatchLogsClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when proper monitoring is configured", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({ logGroups: [mockLogGroup] });

			mockCloudWatchLogsClient
				.on(DescribeMetricFiltersCommand)
				.resolves({ metricFilters: [mockMetricFilter] });

			mockCloudWatchClient
				.on(DescribeAlarmsCommand)
				.resolves({ MetricAlarms: [{ AlarmName: "RootAccountUsageAlarm" }] });

			const result = await checkRootAccountMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-log-group");
		});

		it("should handle multiple log groups with proper configuration", async () => {
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
				.resolves({ MetricAlarms: [{ AlarmName: "RootAccountUsageAlarm" }] });

			const result = await checkRootAccountMonitoring.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no log groups exist", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({ logGroups: [] });

			const result = await checkRootAccountMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No CloudWatch Log Groups found");
		});

		it("should return FAIL when metric filter is missing", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({ logGroups: [mockLogGroup] });

			mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({ metricFilters: [] });

			const result = await checkRootAccountMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("does not have required metric filter");
		});

		it("should return FAIL when alarm is missing", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({ logGroups: [mockLogGroup] });

			mockCloudWatchLogsClient
				.on(DescribeMetricFiltersCommand)
				.resolves({ metricFilters: [mockMetricFilter] });

			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({ MetricAlarms: [] });

			const result = await checkRootAccountMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("No alarms configured");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when CloudWatch Logs API fails", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).rejects(new Error("API Error"));

			const result = await checkRootAccountMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking root account monitoring");
		});

		it("should return ERROR when metric filter check fails", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({ logGroups: [mockLogGroup] });

			mockCloudWatchLogsClient
				.on(DescribeMetricFiltersCommand)
				.rejects(new Error("Metric Filter Error"));

			const result = await checkRootAccountMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking metric filters");
		});
	});
});
