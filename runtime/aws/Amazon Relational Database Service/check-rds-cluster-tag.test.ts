import { RDSClient, DescribeDBClustersCommand, type DBCluster } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsClusterTagCopyCompliance from "./check-rds-cluster-tag";

const mockRDSClient = mockClient(RDSClient);

const mockCompliantCluster: DBCluster = {
	DBClusterIdentifier: "compliant-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:compliant-cluster",
	CopyTagsToSnapshot: true
};

const mockNonCompliantCluster: DBCluster = {
	DBClusterIdentifier: "non-compliant-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:non-compliant-cluster",
	CopyTagsToSnapshot: false
};

describe("checkRdsClusterTagCopyCompliance", () => {
	beforeEach(() => {
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS when cluster has tag copying enabled", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCompliantCluster]
			});

			const result = await checkRdsClusterTagCopyCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("compliant-cluster");
			expect(result.checks[0]?.resourceArn).toBe(mockCompliantCluster.DBClusterArn);
		});

		test("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkRdsClusterTagCopyCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS clusters found in the region");
		});

		test("should handle multiple compliant clusters", async () => {
			const multipleCompliantClusters: DBCluster[] = [
				mockCompliantCluster,
				{ ...mockCompliantCluster, DBClusterIdentifier: "compliant-cluster-2" }
			];

			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: multipleCompliantClusters
			});

			const result = await checkRdsClusterTagCopyCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when cluster has tag copying disabled", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockNonCompliantCluster]
			});

			const result = await checkRdsClusterTagCopyCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"RDS cluster is not configured to copy tags to snapshots"
			);
		});

		test("should handle mixed compliance states", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCompliantCluster, mockNonCompliantCluster]
			});

			const result = await checkRdsClusterTagCopyCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});

		test("should handle clusters with missing identifiers", async () => {
			const incompleteCluster: DBCluster = {
				CopyTagsToSnapshot: true
			};

			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [incompleteCluster]
			});

			const result = await checkRdsClusterTagCopyCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Cluster found without identifier or ARN");
		});
	});

	describe("Error Handling", () => {
		test("should handle API errors gracefully", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).rejects(new Error("API Error"));

			const result = await checkRdsClusterTagCopyCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking RDS clusters: API Error");
		});

		test("should handle undefined DBClusters response", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({});

			const result = await checkRdsClusterTagCopyCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
