import { CloudWatchClient } from "@aws-sdk/client-cloudwatch";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import monitoringTest from "./check-memorydb-monitoring";

const cloudWatchMock = mockClient(CloudWatchClient);

describe("checkMemoryDBMonitoring", () => {
	beforeEach(() => {
		cloudWatchMock.reset();
	});

	it("should fail when no alarms exist", async () => {
		cloudWatchMock.on("DescribeAlarms").resolves({
			MetricAlarms: []
		});

		const results = await monitoringTest.execute();
		expect(results.checks).toHaveLength(1);
		expect(results.checks[0]).toEqual({
			resourceName: "MemoryDB CloudWatch Alarms",
			status: ComplianceStatus.FAIL,
			message: "No CloudWatch alarms found for MemoryDB monitoring"
		});
	});

	it("should fail when essential metrics are not monitored", async () => {
		cloudWatchMock.on("DescribeAlarms").resolves({
			MetricAlarms: [
				{
					AlarmName: "MemoryDB-CPUUtilization",
					AlarmArn: "arn:aws:cloudwatch:us-east-1:123456789012:alarm:MemoryDB-CPUUtilization",
					MetricName: "CPUUtilization",
					ActionsEnabled: true,
					AlarmActions: ["arn:aws:sns:us-east-1:123456789012:alert"],
					EvaluationPeriods: 3
				}
			]
		});

		const results = await monitoringTest.execute();
		expect(results.checks).toContainEqual(
			expect.objectContaining({
				resourceName: "MemoryDB Essential Metrics",
				status: ComplianceStatus.FAIL,
				message: expect.stringContaining("Missing CloudWatch alarms for essential metrics")
			})
		);
	});

	it("should fail for alarms with configuration issues", async () => {
		cloudWatchMock.on("DescribeAlarms").resolves({
			MetricAlarms: [
				{
					AlarmName: "MemoryDB-Test",
					AlarmArn: "arn:aws:cloudwatch:us-east-1:123456789012:alarm:MemoryDB-Test",
					MetricName: "CPUUtilization",
					ActionsEnabled: false,
					AlarmActions: [],
					EvaluationPeriods: 1
				}
			]
		});

		const results = await monitoringTest.execute();
		const alarmCheck = results.checks.find(check => check.resourceName === "MemoryDB-Test");
		expect(alarmCheck).toBeDefined();
		expect(alarmCheck?.status).toBe(ComplianceStatus.FAIL);
		expect(alarmCheck?.message).toContain("Actions are disabled");
		expect(alarmCheck?.message).toContain("No alarm actions configured");
		expect(alarmCheck?.message).toContain("Low evaluation period");
	});

	it("should pass for properly configured alarms", async () => {
		cloudWatchMock.on("DescribeAlarms").resolves({
			MetricAlarms: [
				{
					AlarmName: "MemoryDB-CPUUtilization",
					AlarmArn: "arn:aws:cloudwatch:us-east-1:123456789012:alarm:MemoryDB-CPUUtilization",
					MetricName: "CPUUtilization",
					ActionsEnabled: true,
					AlarmActions: ["arn:aws:sns:us-east-1:123456789012:alert"],
					EvaluationPeriods: 3
				},
				{
					AlarmName: "MemoryDB-Memory",
					AlarmArn: "arn:aws:cloudwatch:us-east-1:123456789012:alarm:MemoryDB-Memory",
					MetricName: "DatabaseMemoryUsagePercentage",
					ActionsEnabled: true,
					AlarmActions: ["arn:aws:sns:us-east-1:123456789012:alert"],
					EvaluationPeriods: 3
				},
				{
					AlarmName: "MemoryDB-Swap",
					AlarmArn: "arn:aws:cloudwatch:us-east-1:123456789012:alarm:MemoryDB-Swap",
					MetricName: "SwapUsage",
					ActionsEnabled: true,
					AlarmActions: ["arn:aws:sns:us-east-1:123456789012:alert"],
					EvaluationPeriods: 3
				},
				{
					AlarmName: "MemoryDB-NetworkIn",
					AlarmArn: "arn:aws:cloudwatch:us-east-1:123456789012:alarm:MemoryDB-NetworkIn",
					MetricName: "NetworkBytesIn",
					ActionsEnabled: true,
					AlarmActions: ["arn:aws:sns:us-east-1:123456789012:alert"],
					EvaluationPeriods: 3
				},
				{
					AlarmName: "MemoryDB-NetworkOut",
					AlarmArn: "arn:aws:cloudwatch:us-east-1:123456789012:alarm:MemoryDB-NetworkOut",
					MetricName: "NetworkBytesOut",
					ActionsEnabled: true,
					AlarmActions: ["arn:aws:sns:us-east-1:123456789012:alert"],
					EvaluationPeriods: 3
				},
				{
					AlarmName: "MemoryDB-Connections",
					AlarmArn: "arn:aws:cloudwatch:us-east-1:123456789012:alarm:MemoryDB-Connections",
					MetricName: "CurrConnections",
					ActionsEnabled: true,
					AlarmActions: ["arn:aws:sns:us-east-1:123456789012:alert"],
					EvaluationPeriods: 3
				}
			]
		});

		const results = await monitoringTest.execute();
		const failedChecks = results.checks.filter(check => check.status === ComplianceStatus.FAIL);
		expect(failedChecks).toHaveLength(0);
	});

	it("should handle API errors", async () => {
		cloudWatchMock.on("DescribeAlarms").rejects(new Error("API Error"));

		const results = await monitoringTest.execute();
		expect(results.checks).toHaveLength(1);
		expect(results.checks[0]).toEqual({
			resourceName: "MemoryDB Monitoring Check",
			status: ComplianceStatus.ERROR,
			message: "Error checking MemoryDB monitoring: API Error"
		});
	});
});
