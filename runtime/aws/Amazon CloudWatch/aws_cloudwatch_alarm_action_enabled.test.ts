// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types";
import checkCloudWatchAlarmActionsEnabled from "./aws_cloudwatch_alarm_action_enabled";

const mockCloudWatchClient = mockClient(CloudWatchClient);

const mockAlarmEnabled = {
	AlarmName: "test-alarm-1",
	AlarmArn: "arn:aws:cloudwatch:us-east-1:123456789012:alarm:test-alarm-1",
	ActionsEnabled: true
};

const mockAlarmDisabled = {
	AlarmName: "test-alarm-2",
	AlarmArn: "arn:aws:cloudwatch:us-east-1:123456789012:alarm:test-alarm-2",
	ActionsEnabled: false
};

describe("checkCloudWatchAlarmActionsEnabled", () => {
	beforeEach(() => {
		mockCloudWatchClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when all alarm actions are enabled", async () => {
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: [mockAlarmEnabled]
			});

			const result = await checkCloudWatchAlarmActionsEnabled.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-alarm-1");
			expect(result.checks[0].resourceArn).toBe(mockAlarmEnabled.AlarmArn);
		});

		it("should handle multiple compliant alarms", async () => {
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: [mockAlarmEnabled, mockAlarmEnabled]
			});

			const result = await checkCloudWatchAlarmActionsEnabled.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when alarm actions are disabled", async () => {
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: [mockAlarmDisabled]
			});

			const result = await checkCloudWatchAlarmActionsEnabled.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("CloudWatch alarm actions are not activated");
		});

		it("should handle mixed compliance states", async () => {
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: [mockAlarmEnabled, mockAlarmDisabled]
			});

			const result = await checkCloudWatchAlarmActionsEnabled.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no alarms exist", async () => {
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: []
			});

			const result = await checkCloudWatchAlarmActionsEnabled.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No CloudWatch alarms found in the region");
		});

		it("should handle pagination", async () => {
			mockCloudWatchClient
				.on(DescribeAlarmsCommand)
				.resolvesOnce({
					MetricAlarms: [mockAlarmEnabled],
					NextToken: "token1"
				})
				.resolvesOnce({
					MetricAlarms: [mockAlarmDisabled]
				});

			const result = await checkCloudWatchAlarmActionsEnabled.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockCloudWatchClient.on(DescribeAlarmsCommand).rejects(new Error("API Error"));

			const result = await checkCloudWatchAlarmActionsEnabled.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudWatch alarms: API Error");
		});

		it("should handle undefined alarm names", async () => {
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: [{ ...mockAlarmEnabled, AlarmName: undefined }]
			});

			const result = await checkCloudWatchAlarmActionsEnabled.execute("us-east-1");
			expect(result.checks[0].resourceName).toBe("Unknown Alarm");
		});
	});
});
