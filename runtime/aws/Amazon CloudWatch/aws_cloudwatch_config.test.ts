import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import {
	CloudWatchLogsClient,
	DescribeLogGroupsCommand,
	DescribeMetricFiltersCommand
} from "@aws-sdk/client-cloudwatch-logs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkConfigChangeMonitoring from "./aws_cloudwatch_config";

const mockCloudWatchClient = mockClient(CloudWatchClient);
const mockCloudWatchLogsClient = mockClient(CloudWatchLogsClient);

const mockLogGroup = {
	logGroupName: "test-log-group",
	arn: "arn:aws:logs:us-east-1:123456789012:log-group:test-log-group"
};

const mockMetricFilter = {
	filterPattern:
		"{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel) ||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }",
	metricTransformations: [{ metricName: "ConfigChanges" }]
};

describe("checkConfigChangeMonitoring", () => {
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
				.resolves({ MetricAlarms: [{ AlarmName: "ConfigChangesAlarm" }] });

			const result = await checkConfigChangeMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe(mockLogGroup.logGroupName);
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
				.resolves({ MetricAlarms: [{ AlarmName: "ConfigChangesAlarm" }] });

			const result = await checkConfigChangeMonitoring.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no log groups exist", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({ logGroups: [] });

			const result = await checkConfigChangeMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No CloudWatch Log Groups found");
		});

		it("should return FAIL when metric filter pattern does not match", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({ logGroups: [mockLogGroup] });

			mockCloudWatchLogsClient
				.on(DescribeMetricFiltersCommand)
				.resolves({ metricFilters: [{ ...mockMetricFilter, filterPattern: "wrong-pattern" }] });

			const result = await checkConfigChangeMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("does not have required metric filter");
		});

		it("should return FAIL when no alarm is configured", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({ logGroups: [mockLogGroup] });

			mockCloudWatchLogsClient
				.on(DescribeMetricFiltersCommand)
				.resolves({ metricFilters: [mockMetricFilter] });

			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({ MetricAlarms: [] });

			const result = await checkConfigChangeMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("No alarm configured");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API calls fail", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).rejects(new Error("API Error"));

			const result = await checkConfigChangeMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudWatch configuration");
		});

		it("should handle missing metric transformations", async () => {
			mockCloudWatchLogsClient.on(DescribeLogGroupsCommand).resolves({ logGroups: [mockLogGroup] });

			mockCloudWatchLogsClient
				.on(DescribeMetricFiltersCommand)
				.resolves({ metricFilters: [{ ...mockMetricFilter, metricTransformations: [] }] });

			const result = await checkConfigChangeMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("does not have a metric transformation");
		});
	});
});
