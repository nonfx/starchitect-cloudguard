//@ts-nocheck
import { RDSClient, DescribeDBClustersCommand, type DBCluster } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsClusterDeletionProtection from "./check-rds-cluster-deletion-protection";

const mockRDSClient = mockClient(RDSClient);

const mockProtectedCluster: DBCluster = {
	DBClusterIdentifier: "protected-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:protected-cluster",
	DeletionProtection: true
};

const mockUnprotectedCluster: DBCluster = {
	DBClusterIdentifier: "unprotected-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:unprotected-cluster",
	DeletionProtection: false
};

describe("checkRdsClusterDeletionProtection", () => {
	beforeEach(() => {
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS when deletion protection is enabled", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockProtectedCluster]
			});

			const result = await checkRdsClusterDeletionProtection.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("protected-cluster");
			expect(result.checks[0]?.resourceArn).toBe(mockProtectedCluster.DBClusterArn);
			expect(result.checks[0]?.message).toBeUndefined();
		});

		test("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkRdsClusterDeletionProtection.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS clusters found in the region");
		});

		test("should handle multiple protected clusters", async () => {
			const multipleProtectedClusters: DBCluster[] = [
				mockProtectedCluster,
				{ ...mockProtectedCluster, DBClusterIdentifier: "protected-cluster-2" }
			];

			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: multipleProtectedClusters
			});

			const result = await checkRdsClusterDeletionProtection.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when deletion protection is disabled", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockUnprotectedCluster]
			});

			const result = await checkRdsClusterDeletionProtection.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"RDS cluster does not have deletion protection enabled"
			);
		});

		test("should handle mixed compliance scenarios", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockProtectedCluster, mockUnprotectedCluster]
			});

			const result = await checkRdsClusterDeletionProtection.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});

		test("should handle clusters without identifiers", async () => {
			const incompleteCluster: DBCluster = {
				DeletionProtection: true
			};

			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [incompleteCluster]
			});

			const result = await checkRdsClusterDeletionProtection.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Cluster found without identifier or ARN");
		});
	});

	describe("Error Handling", () => {
		test("should return ERROR when API call fails", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).rejects(new Error("API Error"));

			const result = await checkRdsClusterDeletionProtection.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking RDS clusters: API Error");
		});

		test("should handle undefined DBClusters response", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({});

			const result = await checkRdsClusterDeletionProtection.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS clusters found in the region");
		});
	});
});
