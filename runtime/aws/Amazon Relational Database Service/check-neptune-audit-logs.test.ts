// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { NeptuneClient, DescribeDBClustersCommand } from "@aws-sdk/client-neptune";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import neptuneAuditLogsCheck from "./check-neptune-audit-logs.js";

const checkNeptuneAuditLogsEnabled = neptuneAuditLogsCheck.execute;

const mockNeptuneClient = mockClient(NeptuneClient);

const mockCompliantCluster = {
	DBClusterIdentifier: "compliant-cluster",
	DBClusterArn: "arn:aws:neptune:us-east-1:123456789012:cluster:compliant-cluster",
	EnabledCloudwatchLogsExports: ["audit"]
};

const mockNonCompliantCluster = {
	DBClusterIdentifier: "non-compliant-cluster",
	DBClusterArn: "arn:aws:neptune:us-east-1:123456789012:cluster:non-compliant-cluster",
	EnabledCloudwatchLogsExports: []
};

describe("checkNeptuneAuditLogsEnabled", () => {
	beforeEach(() => {
		mockNeptuneClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when audit logs are enabled", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCompliantCluster]
			});

			const result = await checkNeptuneAuditLogsEnabled("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("compliant-cluster");
			expect(result.checks[0].resourceArn).toBe(mockCompliantCluster.DBClusterArn);
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkNeptuneAuditLogsEnabled("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Neptune DB clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when audit logs are not enabled", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockNonCompliantCluster]
			});

			const result = await checkNeptuneAuditLogsEnabled("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Neptune DB cluster does not have audit logs enabled for CloudWatch Logs"
			);
		});

		it("should handle mixed compliance scenarios", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCompliantCluster, mockNonCompliantCluster]
			});

			const result = await checkNeptuneAuditLogsEnabled("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle clusters with missing identifiers", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [{ EnabledCloudwatchLogsExports: ["audit"] }]
			});

			const result = await checkNeptuneAuditLogsEnabled("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without identifier or ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).rejects(new Error("API Error"));

			const result = await checkNeptuneAuditLogsEnabled("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking Neptune clusters: API Error");
		});

		it("should handle undefined DBClusters response", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({});

			const result = await checkNeptuneAuditLogsEnabled("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Neptune DB clusters found in the region");
		});
	});
});
