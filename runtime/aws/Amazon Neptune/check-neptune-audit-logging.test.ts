// @ts-nocheck
import { NeptuneClient, DescribeDBClustersCommand } from "@aws-sdk/client-neptune";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkNeptuneAuditLogging from "./check-neptune-audit-logging";

const mockNeptuneClient = mockClient(NeptuneClient);

const mockCompliantCluster = {
	DBClusterIdentifier: "compliant-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:compliant-cluster",
	EnabledCloudwatchLogsExports: ["audit"]
};

const mockNonCompliantCluster = {
	DBClusterIdentifier: "non-compliant-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:non-compliant-cluster",
	EnabledCloudwatchLogsExports: ["error"]
};

describe("checkNeptuneAuditLogging", () => {
	beforeEach(() => {
		mockNeptuneClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when audit logging is enabled", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCompliantCluster]
			});

			const result = await checkNeptuneAuditLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("compliant-cluster");
			expect(result.checks[0].resourceArn).toBe(mockCompliantCluster.DBClusterArn);
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkNeptuneAuditLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Neptune clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when audit logging is not enabled", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockNonCompliantCluster]
			});

			const result = await checkNeptuneAuditLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Audit logging is not enabled for this Neptune cluster"
			);
		});

		it("should handle clusters with no CloudWatch logs exports", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [
					{
						DBClusterIdentifier: "no-logs-cluster",
						DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:no-logs-cluster",
						EnabledCloudwatchLogsExports: []
					}
				]
			});

			const result = await checkNeptuneAuditLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle mixed compliance scenarios", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCompliantCluster, mockNonCompliantCluster]
			});

			const result = await checkNeptuneAuditLogging.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).rejects(new Error("API Error"));

			const result = await checkNeptuneAuditLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Neptune clusters");
		});

		it("should handle clusters with missing identifiers", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [
					{
						EnabledCloudwatchLogsExports: ["audit"]
					}
				]
			});

			const result = await checkNeptuneAuditLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without identifier or ARN");
		});
	});
});
