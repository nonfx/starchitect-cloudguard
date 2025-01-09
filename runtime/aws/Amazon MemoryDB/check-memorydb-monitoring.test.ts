//@ts-nocheck
import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import { MemoryDBClient, DescribeClustersCommand } from "@aws-sdk/client-memorydb";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkMemoryDBMonitoring from "./check-memorydb-monitoring";

const mockCloudWatchClient = mockClient(CloudWatchClient);
const mockMemoryDBClient = mockClient(MemoryDBClient);

const mockCluster = {
	Name: "test-cluster",
	ARN: "arn:aws:memorydb:us-east-1:123456789012:cluster/test-cluster"
};

const mockAlarms = {
	MetricAlarms: [
		{
			MetricName: "CPUUtilization",
			Namespace: "AWS/MemoryDB",
			Dimensions: [{ Name: "ClusterName", Value: "test-cluster" }],
			AlarmName: "test-alarm-1",
			AlarmActions: ["action1"],
			ActionsEnabled: true,
			EvaluationPeriods: 3
		},
		{
			MetricName: "DatabaseMemoryUsagePercentage",
			Namespace: "AWS/MemoryDB",
			Dimensions: [{ Name: "ClusterName", Value: "test-cluster" }],
			AlarmName: "test-alarm-2",
			AlarmActions: ["action1"],
			ActionsEnabled: true,
			EvaluationPeriods: 3
		},
		{
			MetricName: "SwapUsage",
			Namespace: "AWS/MemoryDB",
			Dimensions: [{ Name: "ClusterName", Value: "test-cluster" }],
			AlarmName: "test-alarm-3",
			AlarmActions: ["action1"],
			ActionsEnabled: true,
			EvaluationPeriods: 3
		},
		{
			MetricName: "NetworkBytesIn",
			Namespace: "AWS/MemoryDB",
			Dimensions: [{ Name: "ClusterName", Value: "test-cluster" }],
			AlarmName: "test-alarm-4",
			AlarmActions: ["action1"],
			ActionsEnabled: true,
			EvaluationPeriods: 3
		},
		{
			MetricName: "NetworkBytesOut",
			Namespace: "AWS/MemoryDB",
			Dimensions: [{ Name: "ClusterName", Value: "test-cluster" }],
			AlarmName: "test-alarm-5",
			AlarmActions: ["action1"],
			ActionsEnabled: true,
			EvaluationPeriods: 3
		},
		{
			MetricName: "CurrConnections",
			Namespace: "AWS/MemoryDB",
			Dimensions: [{ Name: "ClusterName", Value: "test-cluster" }],
			AlarmName: "test-alarm-6",
			AlarmActions: ["action1"],
			ActionsEnabled: true,
			EvaluationPeriods: 3
		}
	]
};

describe("checkMemoryDBMonitoring", () => {
	beforeEach(() => {
		mockCloudWatchClient.reset();
		mockMemoryDBClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when all required alarms are configured", async () => {
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves(mockAlarms);

			const result = await checkMemoryDBMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-alarm-1");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when required alarms are missing", async () => {
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: [
					{
						MetricName: "CPUUtilization",
						Namespace: "AWS/MemoryDB",
						Dimensions: [{ Name: "ClusterName", Value: "test-cluster" }]
					}
				]
			});

			const result = await checkMemoryDBMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("Missing CloudWatch alarms for essential metrics");
		});

		it("should return FAIL when no alarms are configured", async () => {
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: []
			});

			const result = await checkMemoryDBMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No CloudWatch alarms found for MemoryDB monitoring");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockCloudWatchClient
				.on(DescribeAlarmsCommand)
				.rejects(new Error("Failed to describe alarms"));

			const result = await checkMemoryDBMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to describe alarms");
		});
	});
});
