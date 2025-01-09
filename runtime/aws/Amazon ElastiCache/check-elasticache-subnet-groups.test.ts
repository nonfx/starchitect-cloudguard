// @ts-nocheck
import { ElastiCacheClient, DescribeCacheClustersCommand } from "@aws-sdk/client-elasticache";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkElastiCacheSubnetGroups from "./check-elasticache-subnet-groups";

const mockElastiCacheClient = mockClient(ElastiCacheClient);

const mockCompliantCluster = {
	CacheClusterId: "compliant-cluster",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:cluster:compliant-cluster",
	CacheSubnetGroupName: "custom-subnet-group"
};

const mockNonCompliantCluster = {
	CacheClusterId: "non-compliant-cluster",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:cluster:non-compliant-cluster",
	CacheSubnetGroupName: "default"
};

describe("checkElastiCacheSubnetGroups", () => {
	beforeEach(() => {
		mockElastiCacheClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when cluster uses custom subnet group", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [mockCompliantCluster]
			});

			const result = await checkElastiCacheSubnetGroups.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("compliant-cluster");
			expect(result.checks[0].resourceArn).toBe(mockCompliantCluster.ARN);
		});

		it("should handle multiple compliant clusters", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [
					mockCompliantCluster,
					{
						...mockCompliantCluster,
						CacheClusterId: "compliant-cluster-2",
						ARN: "arn:aws:elasticache:us-east-1:123456789012:cluster:compliant-cluster-2"
					}
				]
			});

			const result = await checkElastiCacheSubnetGroups.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when cluster uses default subnet group", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [mockNonCompliantCluster]
			});

			const result = await checkElastiCacheSubnetGroups.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"ElastiCache cluster is using the default subnet group"
			);
		});

		it("should handle mixed compliance scenarios", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [mockCompliantCluster, mockNonCompliantCluster]
			});

			const result = await checkElastiCacheSubnetGroups.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases and Error Handling", () => {
		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: []
			});

			const result = await checkElastiCacheSubnetGroups.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No ElastiCache clusters found in the region");
		});

		it("should handle clusters without ID or ARN", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [{ CacheSubnetGroupName: "default" }]
			});

			const result = await checkElastiCacheSubnetGroups.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without ID or ARN");
		});

		it("should handle API errors", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).rejects(new Error("API Error"));

			const result = await checkElastiCacheSubnetGroups.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking ElastiCache clusters: API Error");
		});

		it("should handle pagination", async () => {
			mockElastiCacheClient
				.on(DescribeCacheClustersCommand)
				.resolvesOnce({
					CacheClusters: [mockCompliantCluster],
					Marker: "next-page"
				})
				.resolvesOnce({
					CacheClusters: [mockNonCompliantCluster]
				});

			const result = await checkElastiCacheSubnetGroups.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});
});
