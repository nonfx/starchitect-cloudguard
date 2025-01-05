// @ts-nocheck
import { ElastiCacheClient, DescribeCacheClustersCommand } from "@aws-sdk/client-elasticache";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkElastiCacheVpc from "./check-elasticache-vpc";

const mockElastiCacheClient = mockClient(ElastiCacheClient);

const mockVpcCluster = {
	CacheClusterId: "vpc-cluster",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:cluster:vpc-cluster",
	CacheSubnetGroupName: "subnet-group-1"
};

const mockNonVpcCluster = {
	CacheClusterId: "non-vpc-cluster",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:cluster:non-vpc-cluster"
};

describe("checkElastiCacheVpc", () => {
	beforeEach(() => {
		mockElastiCacheClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when cluster is in VPC", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [mockVpcCluster]
			});

			const result = await checkElastiCacheVpc.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("vpc-cluster");
			expect(result.checks[0].resourceArn).toBe(mockVpcCluster.ARN);
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: []
			});

			const result = await checkElastiCacheVpc.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No ElastiCache clusters found in the region");
		});

		it("should handle multiple compliant clusters", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [
					mockVpcCluster,
					{ ...mockVpcCluster, CacheClusterId: "vpc-cluster-2", ARN: "arn:2" }
				]
			});

			const result = await checkElastiCacheVpc.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when cluster is not in VPC", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [mockNonVpcCluster]
			});

			const result = await checkElastiCacheVpc.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("ElastiCache cluster is not configured to use a VPC");
		});

		it("should handle mixed compliance scenarios", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [mockVpcCluster, mockNonVpcCluster]
			});

			const result = await checkElastiCacheVpc.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle clusters without IDs", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [{ CacheSubnetGroupName: "subnet-1" }]
			});

			const result = await checkElastiCacheVpc.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without ID");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).rejects(new Error("API Error"));

			const result = await checkElastiCacheVpc.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking ElastiCache clusters");
		});

		it("should handle undefined CacheClusters response", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({});

			const result = await checkElastiCacheVpc.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
