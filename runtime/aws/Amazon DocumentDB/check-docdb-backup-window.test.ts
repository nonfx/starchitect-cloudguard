// @ts-nocheck
import { DocDBClient, DescribeDBClustersCommand } from "@aws-sdk/client-docdb";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDocDBBackupWindow from "./check-docdb-backup-window";

const mockDocDBClient = mockClient(DocDBClient);

const mockClusterWithBackupWindow = {
	DBClusterIdentifier: "test-cluster-1",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster-1",
	PreferredBackupWindow: "03:00-04:00"
};

const mockClusterWithoutBackupWindow = {
	DBClusterIdentifier: "test-cluster-2",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster-2",
	PreferredBackupWindow: ""
};

describe("checkDocDBBackupWindow", () => {
	beforeEach(() => {
		mockDocDBClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when cluster has backup window configured", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockClusterWithBackupWindow]
			});

			const result = await checkDocDBBackupWindow.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-cluster-1");
			expect(result.checks[0].resourceArn).toBe(mockClusterWithBackupWindow.DBClusterArn);
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkDocDBBackupWindow.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No DocumentDB clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when cluster has no backup window", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockClusterWithoutBackupWindow]
			});

			const result = await checkDocDBBackupWindow.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"DocumentDB cluster does not have a backup window configured"
			);
		});

		it("should handle clusters without identifiers", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [{ PreferredBackupWindow: "03:00-04:00" }]
			});

			const result = await checkDocDBBackupWindow.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without identifier");
		});

		it("should handle mixed compliance scenarios", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockClusterWithBackupWindow, mockClusterWithoutBackupWindow]
			});

			const result = await checkDocDBBackupWindow.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).rejects(new Error("API Error"));

			const result = await checkDocDBBackupWindow.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking DocumentDB clusters: API Error");
		});

		it("should handle undefined DBClusters response", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({});

			const result = await checkDocDBBackupWindow.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
