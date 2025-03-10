//@ts-nocheck
import { DocDBClient, DescribeDBClustersCommand } from "@aws-sdk/client-docdb";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDocDBClusterAuditLogging from "./check-docdb-audit-logging";

const mockDocDBClient = mockClient(DocDBClient);

const mockCompliantCluster = {
	DBClusterIdentifier: "test-cluster-1",
	DBClusterArn: "arn:aws:docdb:us-east-1:123456789012:cluster:test-cluster-1",
	EnabledCloudwatchLogsExports: ["audit"]
};

const mockNonCompliantCluster = {
	DBClusterIdentifier: "test-cluster-2",
	DBClusterArn: "arn:aws:docdb:us-east-1:123456789012:cluster:test-cluster-2",
	EnabledCloudwatchLogsExports: []
};

describe("checkDocDBClusterAuditLogging", () => {
	beforeEach(() => {
		mockDocDBClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when audit logging is enabled", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCompliantCluster]
			});

			const result = await checkDocDBClusterAuditLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-cluster-1");
			expect(result.checks[0].resourceArn).toBe(mockCompliantCluster.DBClusterArn);
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkDocDBClusterAuditLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No DocumentDB clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when audit logging is not enabled", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockNonCompliantCluster]
			});

			const result = await checkDocDBClusterAuditLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"DocumentDB cluster does not have audit logging enabled to CloudWatch Logs"
			);
		});

		it("should handle mixed compliance scenarios", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCompliantCluster, mockNonCompliantCluster]
			});

			const result = await checkDocDBClusterAuditLogging.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle clusters with missing identifiers", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [{ EnabledCloudwatchLogsExports: ["audit"] }]
			});

			const result = await checkDocDBClusterAuditLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without identifier or ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).rejects(new Error("API Error"));

			const result = await checkDocDBClusterAuditLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking DocumentDB clusters: API Error");
		});

		it("should handle undefined DBClusters response", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({});

			const result = await checkDocDBClusterAuditLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
