//@ts-nocheck
import {
	ElastiCacheClient,
	DescribeUsersCommand,
	DescribeUserGroupsCommand,
	DescribeReplicationGroupsCommand,
	DescribeCacheClustersCommand
} from "@aws-sdk/client-elasticache";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkElastiCacheAuth from "./check-elasticache-auth";

const mockElastiCacheClient = mockClient(ElastiCacheClient);

const mockCluster = {
	CacheClusterId: "test-cluster-1",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:cluster:test-cluster-1"
};

describe("checkElastiCacheAuth", () => {
	beforeEach(() => {
		mockElastiCacheClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			// Simulate no clusters present
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({ CacheClusters: [] });

			const result = await checkElastiCacheAuth.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No ElastiCache clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when authentication is not properly configured", async () => {
			// Simulate a non-compliant cluster with no users or user groups
			mockElastiCacheClient
				.on(DescribeCacheClustersCommand)
				.resolves({ CacheClusters: [mockCluster] })
				.on(DescribeUsersCommand)
				.resolves({ Users: [] })
				.on(DescribeUserGroupsCommand)
				.resolves({ UserGroups: [] })
				.on(DescribeReplicationGroupsCommand)
				.resolves({ ReplicationGroups: [] });

			const result = await checkElastiCacheAuth.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Authentication and access control is not properly configured for the cluster"
			);
		});

		it("should return FAIL when user groups exist but no users are assigned", async () => {
			// Simulate user groups with no assigned users
			mockElastiCacheClient
				.on(DescribeCacheClustersCommand)
				.resolves({ CacheClusters: [mockCluster] })
				.on(DescribeUsersCommand)
				.resolves({ Users: [] })
				.on(DescribeUserGroupsCommand)
				.resolves({ UserGroups: [{ UserIds: [] }] })
				.on(DescribeReplicationGroupsCommand)
				.resolves({ ReplicationGroups: [{ UserGroupIds: ["group1"] }] });

			const result = await checkElastiCacheAuth.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Authentication and access control is not properly configured for the cluster"
			);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			// Simulate an error in the DescribeCacheClustersCommand
			mockElastiCacheClient.on(DescribeCacheClustersCommand).rejects(new Error("API Error"));

			const result = await checkElastiCacheAuth.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking ElastiCache authentication");
		});

		it("should handle missing cluster IDs", async () => {
			// Simulate a cluster with a missing CacheClusterId
			mockElastiCacheClient
				.on(DescribeCacheClustersCommand)
				.resolves({ CacheClusters: [{ ...mockCluster, CacheClusterId: undefined }] })
				.on(DescribeUsersCommand)
				.resolves({ Users: [] })
				.on(DescribeUserGroupsCommand)
				.resolves({ UserGroups: [] })
				.on(DescribeReplicationGroupsCommand)
				.resolves({ ReplicationGroups: [] });

			const result = await checkElastiCacheAuth.execute("us-east-1");
			expect(result.checks).toHaveLength(0);
		});
	});
});
