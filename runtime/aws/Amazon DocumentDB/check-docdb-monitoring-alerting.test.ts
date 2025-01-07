// @ts-nocheck
import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import {
	DocDBClient,
	DescribeDBClustersCommand,
	DescribeDBInstancesCommand
} from "@aws-sdk/client-docdb";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDocDBMonitoringAlerting from "./check-docdb-monitoring-alerting";

const mockCloudWatchClient = mockClient(CloudWatchClient);
const mockDocDBClient = mockClient(DocDBClient);

const mockCluster = {
	DBClusterIdentifier: "test-cluster-1",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster-1"
};

const mockInstance = {
	DBInstanceIdentifier: "test-instance-1",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:test-instance-1"
};

const mockAlarm = {
	AlarmName: "test-alarm",
	Dimensions: [
		{
			Name: "DBClusterIdentifier",
			Value: "test-cluster-1"
		}
	]
};

describe("checkDocDBMonitoringAlerting", () => {
	beforeEach(() => {
		mockCloudWatchClient.reset();
		mockDocDBClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when clusters and instances have alarms configured", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [mockCluster] });
			mockDocDBClient.on(DescribeDBInstancesCommand).resolves({ DBInstances: [mockInstance] });
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: [
					mockAlarm,
					{
						...mockAlarm,
						Dimensions: [
							{
								Name: "DBInstanceIdentifier",
								Value: "test-instance-1"
							}
						]
					}
				]
			});

			const result = await checkDocDBMonitoringAlerting.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});

		it("should return NOTAPPLICABLE when no DocumentDB resources exist", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [] });
			mockDocDBClient.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] });
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({ MetricAlarms: [] });

			const result = await checkDocDBMonitoringAlerting.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No DocumentDB clusters or instances found");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when clusters have no alarms configured", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [mockCluster] });
			mockDocDBClient.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] });
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({ MetricAlarms: [] });

			const result = await checkDocDBMonitoringAlerting.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No CloudWatch alarms configured for this DocumentDB cluster"
			);
		});

		it("should return FAIL when instances have no alarms configured", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [] });
			mockDocDBClient.on(DescribeDBInstancesCommand).resolves({ DBInstances: [mockInstance] });
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({ MetricAlarms: [] });

			const result = await checkDocDBMonitoringAlerting.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No CloudWatch alarms configured for this DocumentDB instance"
			);
		});

		it("should handle mixed compliance scenarios", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [mockCluster] });
			mockDocDBClient.on(DescribeDBInstancesCommand).resolves({ DBInstances: [mockInstance] });
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({ MetricAlarms: [mockAlarm] });

			const result = await checkDocDBMonitoringAlerting.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API calls fail", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).rejects(new Error("API Error"));

			const result = await checkDocDBMonitoringAlerting.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking DocumentDB monitoring");
		});

		it("should handle missing resource identifiers", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [{ ...mockCluster, DBClusterIdentifier: undefined }]
			});

			// Add mocks for other required API calls
			mockDocDBClient.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] }); // No instances

			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({ MetricAlarms: [] }); // No alarms

			const result = await checkDocDBMonitoringAlerting.execute("us-east-1");
			expect(result.checks).toHaveLength(0);
		});
	});
});
