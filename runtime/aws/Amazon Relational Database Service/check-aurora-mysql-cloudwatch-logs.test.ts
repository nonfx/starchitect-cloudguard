//@ts-nocheck
import { RDSClient, DescribeDBClustersCommand, type DBCluster } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types";
import checkAuroraMysqlCloudWatchLogs from "./check-aurora-mysql-cloudwatch-logs";

const mockRDSClient = mockClient(RDSClient);

const mockAuroraMySQLClusterWithLogs: DBCluster = {
	DBClusterIdentifier: "aurora-cluster-1",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:aurora-cluster-1",
	Engine: "aurora-mysql",
	EnabledCloudwatchLogsExports: ["audit", "error", "general", "slowquery"]
};

const mockAuroraMySQLClusterWithoutLogs: DBCluster = {
	DBClusterIdentifier: "aurora-cluster-2",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:aurora-cluster-2",
	Engine: "aurora-mysql",
	EnabledCloudwatchLogsExports: ["error", "general"]
};

const mockPostgresCluster: DBCluster = {
	DBClusterIdentifier: "postgres-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:postgres-cluster",
	Engine: "aurora-postgresql",
	EnabledCloudwatchLogsExports: ["postgresql"]
};

describe("checkAuroraMysqlCloudWatchLogs", () => {
	beforeEach(() => {
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Aurora MySQL cluster has audit logs enabled", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockAuroraMySQLClusterWithLogs]
			});

			const result = await checkAuroraMysqlCloudWatchLogs.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("aurora-cluster-1");
			expect(result.checks[0].resourceArn).toBe(mockAuroraMySQLClusterWithLogs.DBClusterArn);
		});

		it("should ignore non-Aurora-MySQL clusters", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockPostgresCluster]
			});

			const result = await checkAuroraMysqlCloudWatchLogs.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Aurora MySQL DB clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when Aurora MySQL cluster does not have audit logs enabled", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockAuroraMySQLClusterWithoutLogs]
			});

			const result = await checkAuroraMysqlCloudWatchLogs.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Aurora MySQL cluster does not have audit logs enabled in CloudWatch Logs exports"
			);
		});

		it("should handle mixed compliance scenarios", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [
					mockAuroraMySQLClusterWithLogs,
					mockAuroraMySQLClusterWithoutLogs,
					mockPostgresCluster
				]
			});

			const result = await checkAuroraMysqlCloudWatchLogs.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no DB clusters exist", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkAuroraMysqlCloudWatchLogs.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Aurora MySQL DB clusters found in the region");
		});

		it("should handle undefined EnabledCloudwatchLogsExports", async () => {
			const clusterWithoutLogs: DBCluster = {
				...mockAuroraMySQLClusterWithoutLogs,
				EnabledCloudwatchLogsExports: undefined
			};

			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [clusterWithoutLogs]
			});

			const result = await checkAuroraMysqlCloudWatchLogs.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockRDSClient
				.on(DescribeDBClustersCommand)
				.rejects(new Error("Failed to describe DB clusters"));

			const result = await checkAuroraMysqlCloudWatchLogs.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to describe DB clusters");
		});
	});
});
