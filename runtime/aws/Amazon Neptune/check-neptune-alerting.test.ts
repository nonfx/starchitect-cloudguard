// @ts-nocheck
import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import { NeptuneClient, DescribeDBClustersCommand } from "@aws-sdk/client-neptune";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkNeptuneAlerting from "./check-neptune-alerting";

const mockNeptuneClient = mockClient(NeptuneClient);
const mockCloudWatchClient = mockClient(CloudWatchClient);

const mockNeptuneCluster = {
	DBClusterIdentifier: "test-cluster-1",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster-1"
};

const mockCloudWatchAlarm = {
	AlarmName: "test-cluster-1-cpu-alarm",
	MetricName: "CPUUtilization",
	Namespace: "AWS/Neptune",
	Dimensions: [
		{
			Name: "DBClusterIdentifier",
			Value: "test-cluster-1"
		}
	]
};

describe("checkNeptuneAlerting", () => {
	beforeEach(() => {
		mockNeptuneClient.reset();
		mockCloudWatchClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Neptune cluster has associated CloudWatch alarms", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockNeptuneCluster]
			});
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: [mockCloudWatchAlarm]
			});

			const result = await checkNeptuneAlerting.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-cluster-1");
			expect(result.checks[0].resourceArn).toBe(mockNeptuneCluster.DBClusterArn);
		});

		it("should return NOTAPPLICABLE when no Neptune clusters exist", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkNeptuneAlerting.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Neptune clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when Neptune cluster has no CloudWatch alarms", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockNeptuneCluster]
			});
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: []
			});

			const result = await checkNeptuneAlerting.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Neptune cluster does not have any associated CloudWatch alarms for alerting"
			);
		});

		it("should handle clusters without identifiers", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [{ DBClusterArn: "arn:invalid" }]
			});

			const result = await checkNeptuneAlerting.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Neptune cluster found without identifier");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when Neptune API call fails", async () => {
			mockNeptuneClient
				.on(DescribeDBClustersCommand)
				.rejects(new Error("Failed to describe Neptune clusters"));

			const result = await checkNeptuneAlerting.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Neptune clusters");
		});

		it("should return ERROR when CloudWatch API call fails", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockNeptuneCluster]
			});
			mockCloudWatchClient
				.on(DescribeAlarmsCommand)
				.rejects(new Error("Failed to describe CloudWatch alarms"));

			const result = await checkNeptuneAlerting.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Neptune clusters");
		});
	});

	it("should handle multiple Neptune clusters with mixed compliance", async () => {
		mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
			DBClusters: [
				mockNeptuneCluster,
				{
					DBClusterIdentifier: "test-cluster-2",
					DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster-2"
				}
			]
		});
		mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
			MetricAlarms: [mockCloudWatchAlarm] // Only has alarm for test-cluster-1
		});

		const result = await checkNeptuneAlerting.execute("us-east-1");
		expect(result.checks).toHaveLength(2);
		expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
	});
});
