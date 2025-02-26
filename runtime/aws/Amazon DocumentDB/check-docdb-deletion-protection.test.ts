// @ts-nocheck
import { DocDBClient, DescribeDBClustersCommand } from "@aws-sdk/client-docdb";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDocDBDeletionProtection from "./check-docdb-deletion-protection";

const mockDocDBClient = mockClient(DocDBClient);

const mockProtectedCluster = {
	DBClusterIdentifier: "protected-cluster",
	DBClusterArn: "arn:aws:docdb:us-east-1:123456789012:cluster:protected-cluster",
	DeletionProtection: true
};

const mockUnprotectedCluster = {
	DBClusterIdentifier: "unprotected-cluster",
	DBClusterArn: "arn:aws:docdb:us-east-1:123456789012:cluster:unprotected-cluster",
	DeletionProtection: false
};

describe("checkDocDBDeletionProtection", () => {
	beforeEach(() => {
		mockDocDBClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when deletion protection is enabled", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockProtectedCluster]
			});

			const result = await checkDocDBDeletionProtection.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("protected-cluster");
			expect(result.checks[0].resourceArn).toBe(mockProtectedCluster.DBClusterArn);
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkDocDBDeletionProtection.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No DocumentDB clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when deletion protection is disabled", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockUnprotectedCluster]
			});

			const result = await checkDocDBDeletionProtection.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"DocumentDB cluster does not have deletion protection enabled"
			);
		});

		it("should handle multiple clusters with mixed compliance", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockProtectedCluster, mockUnprotectedCluster]
			});

			const result = await checkDocDBDeletionProtection.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle clusters without identifiers", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [{ DeletionProtection: true }]
			});

			const result = await checkDocDBDeletionProtection.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without identifier or ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).rejects(new Error("API Error"));

			const result = await checkDocDBDeletionProtection.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking DocumentDB clusters: API Error");
		});

		it("should handle undefined DBClusters response", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({});

			const result = await checkDocDBDeletionProtection.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No DocumentDB clusters found in the region");
		});
	});
});
