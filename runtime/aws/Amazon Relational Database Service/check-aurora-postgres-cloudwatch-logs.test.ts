//@ts-nocheck
import { RDSClient, DescribeDBClustersCommand, type DBCluster } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkAuroraPostgresCloudWatchLogs from "./check-aurora-postgres-cloudwatch-logs";

const mockRDSClient = mockClient(RDSClient);

const mockCompliantCluster: DBCluster = {
	DBClusterIdentifier: "compliant-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:compliant-cluster",
	Engine: "aurora-postgresql",
	EnabledCloudwatchLogsExports: ["postgresql"]
};

const mockNonCompliantCluster: DBCluster = {
	DBClusterIdentifier: "non-compliant-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:non-compliant-cluster",
	Engine: "aurora-postgresql",
	EnabledCloudwatchLogsExports: []
};

describe("checkAuroraPostgresCloudWatchLogs", () => {
	beforeEach(() => {
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when PostgreSQL logs are enabled", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCompliantCluster]
			});

			const result = await checkAuroraPostgresCloudWatchLogs.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("compliant-cluster");
			expect(result.checks[0].resourceArn).toBe(mockCompliantCluster.DBClusterArn);
		});

		it("should return NOTAPPLICABLE when no DB clusters exist", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkAuroraPostgresCloudWatchLogs.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Aurora PostgreSQL DB clusters found in the region");
		});

		it("should return NOTAPPLICABLE when no PostgreSQL clusters exist", async () => {
			const mysqlCluster: DBCluster = {
				DBClusterIdentifier: "mysql-cluster",
				Engine: "aurora-mysql"
			};

			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mysqlCluster]
			});

			const result = await checkAuroraPostgresCloudWatchLogs.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when PostgreSQL logs are not enabled", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockNonCompliantCluster]
			});

			const result = await checkAuroraPostgresCloudWatchLogs.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("not configured to publish PostgreSQL logs");
		});

		it("should handle mixed compliance scenarios", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCompliantCluster, mockNonCompliantCluster]
			});

			const result = await checkAuroraPostgresCloudWatchLogs.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle clusters without identifiers", async () => {
			const incompleteCluster: DBCluster = {
				Engine: "aurora-postgresql"
			};

			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [incompleteCluster]
			});

			const result = await checkAuroraPostgresCloudWatchLogs.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Cluster found without identifier or ARN");
		});
	});

	describe("Error Handling", () => {
		it("should handle API errors", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).rejects(new Error("API Error"));

			const result = await checkAuroraPostgresCloudWatchLogs.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Aurora PostgreSQL clusters");
		});

		it("should handle undefined DBClusters response", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({});

			const result = await checkAuroraPostgresCloudWatchLogs.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
