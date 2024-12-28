//@ts-nocheck
import { RDSClient, DescribeDBClustersCommand, type DBCluster } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsClusterIamAuth from "./check-rds-cluster-iam-auth";

const mockRdsClient = mockClient(RDSClient);

const mockClusterWithIamAuth: DBCluster = {
	DBClusterIdentifier: "test-cluster-1",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster-1",
	IAMDatabaseAuthenticationEnabled: true
};

const mockClusterWithoutIamAuth: DBCluster = {
	DBClusterIdentifier: "test-cluster-2",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster-2",
	IAMDatabaseAuthenticationEnabled: false
};

describe("checkRdsClusterIamAuth", () => {
	beforeEach(() => {
		mockRdsClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS when IAM authentication is enabled", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockClusterWithIamAuth]
			});

			const result = await checkRdsClusterIamAuth.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-cluster-1");
			expect(result.checks[0]?.resourceArn).toBe(mockClusterWithIamAuth.DBClusterArn);
		});

		test("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkRdsClusterIamAuth.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when IAM authentication is disabled", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockClusterWithoutIamAuth]
			});

			const result = await checkRdsClusterIamAuth.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"IAM authentication is not enabled for this RDS cluster"
			);
		});

		test("should handle multiple clusters with mixed compliance", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockClusterWithIamAuth, mockClusterWithoutIamAuth]
			});

			const result = await checkRdsClusterIamAuth.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});

		test("should return ERROR for clusters without identifiers", async () => {
			const incompleteCluster: DBCluster = {
				IAMDatabaseAuthenticationEnabled: true
			};

			mockRdsClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [incompleteCluster]
			});

			const result = await checkRdsClusterIamAuth.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Cluster found without identifier or ARN");
		});
	});

	describe("Error Handling", () => {
		test("should return ERROR when API call fails", async () => {
			mockRdsClient
				.on(DescribeDBClustersCommand)
				.rejects(new Error("Failed to describe DB clusters"));

			const result = await checkRdsClusterIamAuth.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS clusters");
		});

		test("should handle undefined DBClusters response", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).resolves({});

			const result = await checkRdsClusterIamAuth.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
