// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkCloudWatchAlarmActions from "./aws_cloudwatch_alarm_action_check";

const mockCloudWatchClient = mockClient(CloudWatchClient);

const mockAlarmWithActions = {
	AlarmName: "test-alarm-1",
	AlarmArn: "arn:aws:cloudwatch:us-east-1:123456789012:alarm:test-alarm-1",
	AlarmActions: ["arn:aws:sns:us-east-1:123456789012:test-topic"]
};

const mockAlarmWithoutActions = {
	AlarmName: "test-alarm-2",
	AlarmArn: "arn:aws:cloudwatch:us-east-1:123456789012:alarm:test-alarm-2",
	AlarmActions: []
};

describe("checkCloudWatchAlarmActions", () => {
	beforeEach(() => {
		mockCloudWatchClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when alarm has actions configured", async () => {
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: [mockAlarmWithActions]
			});

			const result = await checkCloudWatchAlarmActions.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-alarm-1");
			expect(result.checks[0].resourceArn).toBe(mockAlarmWithActions.AlarmArn);
		});

		it("should handle multiple compliant alarms", async () => {
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: [mockAlarmWithActions, mockAlarmWithActions]
			});

			const result = await checkCloudWatchAlarmActions.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when alarm has no actions configured", async () => {
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: [mockAlarmWithoutActions]
			});

			const result = await checkCloudWatchAlarmActions.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"CloudWatch alarm does not have any actions configured for ALARM state"
			);
		});

		it("should handle mixed compliance states", async () => {
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: [mockAlarmWithActions, mockAlarmWithoutActions]
			});

			const result = await checkCloudWatchAlarmActions.execute("us-east-1");
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

			const result = await checkCloudWatchAlarmActions.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No CloudWatch alarms found in the region");
		});

		it("should handle alarms without names", async () => {
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: [{ AlarmActions: [] }]
			});

			const result = await checkCloudWatchAlarmActions.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Alarm found without name");
		});
	});

	describe("Pagination", () => {
		it("should handle paginated results", async () => {
			mockCloudWatchClient
				.on(DescribeAlarmsCommand)
				.resolvesOnce({
					MetricAlarms: [mockAlarmWithActions],
					NextToken: "token1"
				})
				.resolvesOnce({
					MetricAlarms: [mockAlarmWithoutActions]
				});

			const result = await checkCloudWatchAlarmActions.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockCloudWatchClient.on(DescribeAlarmsCommand).rejects(new Error("API Error"));

			const result = await checkCloudWatchAlarmActions.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking CloudWatch alarms: API Error");
		});
	});
});
