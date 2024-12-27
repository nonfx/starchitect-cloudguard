import { RDSClient, DescribeDBClustersCommand } from "@aws-sdk/client-rds";
import { CloudTrailClient, DescribeTrailsCommand } from "@aws-sdk/client-cloudtrail";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkAuroraAuditLoggingCompliance from "./check-aurora-audit-logging";

const mockRDSClient = mockClient(RDSClient);
const mockCloudTrailClient = mockClient(CloudTrailClient);

const mockAuroraCluster = {
	DBClusterIdentifier: "test-aurora-1",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:test-aurora-1",
	ActivityStreamStatus: "started"
};

const mockCloudTrail = {
	Name: "test-trail",
	IsMultiRegionTrail: true,
	IncludeGlobalServiceEvents: true
};

describe("checkAuroraAuditLoggingCompliance", () => {
	beforeEach(() => {
		mockRDSClient.reset();
		mockCloudTrailClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Database Activity Stream is enabled", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: []
			});
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockAuroraCluster]
			});

			const result = await checkAuroraAuditLoggingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-aurora-1");
		});

		it("should return PASS when CloudTrail is properly configured", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [mockCloudTrail]
			});
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [
					{
						...mockAuroraCluster,
						ActivityStreamStatus: "stopped"
					}
				]
			});

			const result = await checkAuroraAuditLoggingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-aurora-1");
		});

		it("should return NOTAPPLICABLE when no Aurora clusters exist", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [mockCloudTrail]
			});
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkAuroraAuditLoggingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Aurora clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when neither Activity Stream nor CloudTrail is configured", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: []
			});
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [
					{
						...mockAuroraCluster,
						ActivityStreamStatus: "stopped"
					}
				]
			});

			const result = await checkAuroraAuditLoggingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Neither CloudTrail nor Database Activity Stream is enabled for this Aurora cluster"
			);
		});

		it("should handle multiple clusters with mixed compliance", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: []
			});
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [
					mockAuroraCluster,
					{
						...mockAuroraCluster,
						DBClusterIdentifier: "test-aurora-2",
						ActivityStreamStatus: "stopped"
					}
				]
			});

			const result = await checkAuroraAuditLoggingCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when RDS API call fails", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [mockCloudTrail]
			});
			mockRDSClient.on(DescribeDBClustersCommand).rejects(new Error("RDS API Error"));

			const result = await checkAuroraAuditLoggingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("RDS API Error");
		});

		it("should return ERROR when CloudTrail API call fails", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).rejects(new Error("CloudTrail API Error"));

			const result = await checkAuroraAuditLoggingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Aurora audit logging");
		});
	});
});
