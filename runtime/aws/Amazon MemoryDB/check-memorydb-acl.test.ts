// @ts-nocheck
import {
	MemoryDBClient,
	DescribeClustersCommand,
	DescribeUsersCommand,
	DescribeACLsCommand
} from "@aws-sdk/client-memorydb";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkMemoryDBACL from "./check-memorydb-acl";

const mockMemoryDBClient = mockClient(MemoryDBClient);

const mockCluster = {
	Name: "test-cluster",
	ARN: "arn:aws:memorydb:us-east-1:123456789012:cluster/test-cluster",
	ACLName: "test-acl"
};

const mockACL = {
	Name: "test-acl",
	UserNames: ["user1", "user2"]
};

const mockUsers = [
	{
		Name: "user1",
		AuthenticationMode: { Type: "password" },
		AccessString: "on ~* +@read"
	},
	{
		Name: "user2",
		AuthenticationMode: { Type: "iam" },
		AccessString: "on ~* +@write"
	}
];

describe("checkMemoryDBACL", () => {
	beforeEach(() => {
		mockMemoryDBClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when clusters have properly configured ACLs", async () => {
			mockMemoryDBClient
				.on(DescribeClustersCommand)
				.resolves({ Clusters: [mockCluster] })
				.on(DescribeACLsCommand)
				.resolves({ ACLs: [mockACL] })
				.on(DescribeUsersCommand)
				.resolves({ Users: mockUsers });

			const result = await checkMemoryDBACL.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-cluster");
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockMemoryDBClient.on(DescribeClustersCommand).resolves({ Clusters: [] });

			const result = await checkMemoryDBACL.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No MemoryDB clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when cluster has no ACL configured", async () => {
			const clusterWithoutACL = { ...mockCluster, ACLName: undefined };
			mockMemoryDBClient
				.on(DescribeClustersCommand)
				.resolves({ Clusters: [clusterWithoutACL] })
				.on(DescribeACLsCommand)
				.resolves({ ACLs: [] })
				.on(DescribeUsersCommand)
				.resolves({ Users: [] });

			const result = await checkMemoryDBACL.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Cluster does not have an ACL configured");
		});

		it("should return FAIL when users have overly permissive access", async () => {
			const permissiveUser = {
				Name: "user1",
				AuthenticationMode: { Type: "password" },
				AccessString: "all"
			};

			mockMemoryDBClient
				.on(DescribeClustersCommand)
				.resolves({ Clusters: [mockCluster] })
				.on(DescribeACLsCommand)
				.resolves({ ACLs: [mockACL] })
				.on(DescribeUsersCommand)
				.resolves({ Users: [permissiveUser] });

			const result = await checkMemoryDBACL.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("User has overly permissive access string");
		});

		it("should return FAIL when users have invalid authentication type", async () => {
			const invalidAuthUser = {
				Name: "user1",
				AuthenticationMode: { Type: "invalid" },
				AccessString: "on ~* +@read"
			};

			mockMemoryDBClient
				.on(DescribeClustersCommand)
				.resolves({ Clusters: [mockCluster] })
				.on(DescribeACLsCommand)
				.resolves({ ACLs: [mockACL] })
				.on(DescribeUsersCommand)
				.resolves({ Users: [invalidAuthUser] });

			const result = await checkMemoryDBACL.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("User has invalid authentication type");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API calls fail", async () => {
			mockMemoryDBClient.on(DescribeClustersCommand).rejects(new Error("API Error"));

			const result = await checkMemoryDBACL.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking MemoryDB clusters");
		});

		it("should handle clusters without names", async () => {
			const invalidCluster = { ARN: "test-arn" };
			mockMemoryDBClient.on(DescribeClustersCommand).resolves({ Clusters: [invalidCluster] });

			const result = await checkMemoryDBACL.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without name");
		});
	});
});
