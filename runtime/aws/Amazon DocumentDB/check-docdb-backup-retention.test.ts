//@ts-nocheck
import { DocDBClient, DescribeDBClustersCommand } from "@aws-sdk/client-docdb";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDocDBBackupRetention from "./check-docdb-backup-retention";

const mockDocDBClient = mockClient(DocDBClient);

const mockCompliantCluster = {
	DBClusterIdentifier: "compliant-cluster",
	DBClusterArn: "arn:aws:docdb:us-east-1:123456789012:cluster:compliant-cluster",
	BackupRetentionPeriod: 7
};

const mockNonCompliantCluster = {
	DBClusterIdentifier: "non-compliant-cluster",
	DBClusterArn: "arn:aws:docdb:us-east-1:123456789012:cluster:non-compliant-cluster",
	BackupRetentionPeriod: 5
};

describe("checkDocDBBackupRetention", () => {
	beforeEach(() => {
		mockDocDBClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when backup retention period meets minimum requirement", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCompliantCluster]
			});

			const result = await checkDocDBBackupRetention.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("compliant-cluster");
			expect(result.checks[0].resourceArn).toBe(mockCompliantCluster.DBClusterArn);
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkDocDBBackupRetention.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No DocumentDB clusters found in the region");
		});

		it("should handle multiple compliant clusters", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [
					{ ...mockCompliantCluster },
					{
						...mockCompliantCluster,
						DBClusterIdentifier: "compliant-cluster-2",
						DBClusterArn: "arn:2"
					}
				]
			});

			const result = await checkDocDBBackupRetention.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when backup retention period is below minimum", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockNonCompliantCluster]
			});

			const result = await checkDocDBBackupRetention.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain(
				"Backup retention period (5 days) is less than the required 7 days"
			);
		});

		it("should handle mixed compliance scenarios", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCompliantCluster, mockNonCompliantCluster]
			});

			const result = await checkDocDBBackupRetention.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle clusters with missing backup retention period", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [
					{
						DBClusterIdentifier: "no-retention-cluster",
						DBClusterArn: "arn:3"
					}
				]
			});

			const result = await checkDocDBBackupRetention.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).rejects(new Error("API Error"));

			const result = await checkDocDBBackupRetention.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking DocumentDB clusters");
		});

		it("should handle clusters with missing identifiers", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [{ BackupRetentionPeriod: 7 }]
			});

			const result = await checkDocDBBackupRetention.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without identifier or ARN");
		});
	});
});
