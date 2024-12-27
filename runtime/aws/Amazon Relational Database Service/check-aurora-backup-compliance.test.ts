//@ts-nocheck
import { RDSClient, DescribeDBClustersCommand, type DBCluster } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkAuroraBackupCompliance from "./check-aurora-backup-compliance";

const mockRDSClient = mockClient(RDSClient);

const mockValidCluster: DBCluster = {
	DBClusterIdentifier: "valid-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:valid-cluster",
	BackupRetentionPeriod: 7
};

const mockInvalidCluster: DBCluster = {
	DBClusterIdentifier: "invalid-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:invalid-cluster",
	BackupRetentionPeriod: 0
};

describe("checkAuroraBackupCompliance", () => {
	beforeEach(() => {
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for clusters with valid backup retention period", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockValidCluster]
			});

			const result = await checkAuroraBackupCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("valid-cluster");
			expect(result.checks[0].resourceArn).toBe(mockValidCluster.DBClusterArn);
		});

		it("should handle multiple compliant clusters", async () => {
			const multipleValidClusters: DBCluster[] = [
				{ ...mockValidCluster },
				{
					...mockValidCluster,
					DBClusterIdentifier: "valid-cluster-2",
					DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:valid-cluster-2",
					BackupRetentionPeriod: 35
				}
			];

			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: multipleValidClusters
			});

			const result = await checkAuroraBackupCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for clusters with invalid backup retention period", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockInvalidCluster]
			});

			const result = await checkAuroraBackupCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("Invalid backup retention period");
		});

		it("should handle mixed compliance scenarios", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockValidCluster, mockInvalidCluster]
			});

			const result = await checkAuroraBackupCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle clusters with missing identifiers", async () => {
			const invalidClusterData: DBCluster = {
				BackupRetentionPeriod: 7
			};

			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [invalidClusterData]
			});

			const result = await checkAuroraBackupCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Cluster found without identifier or ARN");
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkAuroraBackupCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Aurora clusters found in the region");
		});

		it("should return ERROR when API call fails", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).rejects(new Error("API call failed"));

			const result = await checkAuroraBackupCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Aurora clusters");
		});

		it("should handle undefined DBClusters in response", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({});

			const result = await checkAuroraBackupCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
