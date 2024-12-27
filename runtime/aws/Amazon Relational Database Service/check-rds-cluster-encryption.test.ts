//@ts-nocheck
import { RDSClient, DescribeDBClustersCommand, type DBCluster } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsClusterEncryption from "./check-rds-cluster-encryption";

const mockRdsClient = mockClient(RDSClient);

const mockEncryptedCluster: DBCluster = {
	DBClusterIdentifier: "encrypted-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:encrypted-cluster",
	StorageEncrypted: true
};

const mockUnencryptedCluster: DBCluster = {
	DBClusterIdentifier: "unencrypted-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:unencrypted-cluster",
	StorageEncrypted: false
};

describe("checkRdsClusterEncryption", () => {
	beforeEach(() => {
		mockRdsClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS when all clusters are encrypted", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockEncryptedCluster]
			});

			const result = await checkRdsClusterEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("encrypted-cluster");
			expect(result.checks[0]?.resourceArn).toBe(mockEncryptedCluster.DBClusterArn);
		});

		test("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkRdsClusterEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when clusters are not encrypted", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockUnencryptedCluster]
			});

			const result = await checkRdsClusterEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe("RDS cluster is not encrypted at rest");
		});

		test("should handle mixed encrypted and unencrypted clusters", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockEncryptedCluster, mockUnencryptedCluster]
			});

			const result = await checkRdsClusterEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});

		test("should handle clusters with missing identifiers", async () => {
			const incompleteCluster: DBCluster = {
				StorageEncrypted: true
			};

			mockRdsClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [incompleteCluster]
			});

			const result = await checkRdsClusterEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Cluster found without identifier or ARN");
		});
	});

	describe("Error Handling", () => {
		test("should return ERROR when API call fails", async () => {
			mockRdsClient
				.on(DescribeDBClustersCommand)
				.rejects(new Error("Failed to describe DB clusters"));

			const result = await checkRdsClusterEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS clusters");
		});

		test("should handle undefined DBClusters response", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).resolves({});

			const result = await checkRdsClusterEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
