import { RDSClient, DescribeDBClustersCommand, type DBCluster } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsClusterMultiAz from "./check-rds-cluster-multi-az";

const mockRdsClient = mockClient(RDSClient);

const mockMultiAZCluster: DBCluster = {
	DBClusterIdentifier: "multi-az-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:multi-az-cluster",
	AvailabilityZones: ["us-east-1a", "us-east-1b", "us-east-1c"]
};

const mockSingleAZCluster: DBCluster = {
	DBClusterIdentifier: "single-az-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:single-az-cluster",
	AvailabilityZones: ["us-east-1a"]
};

describe("checkRdsClusterMultiAz", () => {
	beforeEach(() => {
		mockRdsClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS when cluster has multiple AZs", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockMultiAZCluster]
			});

			const result = await checkRdsClusterMultiAz.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("multi-az-cluster");
			expect(result.checks[0]?.resourceArn).toBe(mockMultiAZCluster.DBClusterArn);
		});

		test("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkRdsClusterMultiAz.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when cluster has single AZ", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockSingleAZCluster]
			});

			const result = await checkRdsClusterMultiAz.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"RDS cluster is not configured with multiple Availability Zones"
			);
		});

		test("should handle mixed compliance scenarios", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockMultiAZCluster, mockSingleAZCluster]
			});

			const result = await checkRdsClusterMultiAz.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});

		test("should handle clusters without identifiers", async () => {
			const incompleteCluster: DBCluster = {
				AvailabilityZones: ["us-east-1a"]
			};

			mockRdsClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [incompleteCluster]
			});

			const result = await checkRdsClusterMultiAz.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Cluster found without identifier or ARN");
		});
	});

	describe("Error Handling", () => {
		test("should return ERROR when API call fails", async () => {
			mockRdsClient
				.on(DescribeDBClustersCommand)
				.rejects(new Error("Failed to describe DB clusters"));

			const result = await checkRdsClusterMultiAz.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS clusters");
		});

		test("should handle undefined DBClusters response", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).resolves({});

			const result = await checkRdsClusterMultiAz.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
