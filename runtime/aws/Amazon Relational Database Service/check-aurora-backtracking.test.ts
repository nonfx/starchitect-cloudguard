import { RDSClient, DescribeDBClustersCommand, type DBCluster } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkAuroraBacktrackingCompliance from "./check-aurora-backtracking";

const mockRDSClient = mockClient(RDSClient);

const mockAuroraClusterWithBacktracking: DBCluster = {
	DBClusterIdentifier: "aurora-cluster-1",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:aurora-cluster-1",
	Engine: "aurora-mysql",
	BacktrackWindow: 72 // hours
};

const mockAuroraClusterWithoutBacktracking: DBCluster = {
	DBClusterIdentifier: "aurora-cluster-2",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:aurora-cluster-2",
	Engine: "aurora-mysql",
	BacktrackWindow: 0
};

const mockNonAuroraCluster: DBCluster = {
	DBClusterIdentifier: "postgres-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:postgres-cluster",
	Engine: "postgres"
};

describe("checkAuroraBacktrackingCompliance", () => {
	beforeEach(() => {
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Aurora cluster has backtracking enabled", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockAuroraClusterWithBacktracking]
			});

			const result = await checkAuroraBacktrackingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("aurora-cluster-1");
			expect(result.checks[0].resourceArn).toBe(mockAuroraClusterWithBacktracking.DBClusterArn);
		});

		it("should return NOTAPPLICABLE for non-Aurora clusters", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockNonAuroraCluster]
			});

			const result = await checkAuroraBacktrackingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("Not an Aurora cluster");
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkAuroraBacktrackingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Aurora clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when Aurora cluster has backtracking disabled", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockAuroraClusterWithoutBacktracking]
			});

			const result = await checkAuroraBacktrackingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Aurora cluster does not have backtracking enabled");
		});

		it("should handle mixed compliance scenarios", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [
					mockAuroraClusterWithBacktracking,
					mockAuroraClusterWithoutBacktracking,
					mockNonAuroraCluster
				]
			});

			const result = await checkAuroraBacktrackingCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(3);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[2].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});

		it("should handle clusters without identifiers", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [{ Engine: "aurora" } as DBCluster]
			});

			const result = await checkAuroraBacktrackingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without identifier or ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).rejects(new Error("API call failed"));

			const result = await checkAuroraBacktrackingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Aurora clusters");
		});
	});
});
