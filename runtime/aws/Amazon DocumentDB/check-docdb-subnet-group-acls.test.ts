// @ts-nocheck
import {
	DocDBClient,
	DescribeDBClustersCommand,
	DescribeDBSubnetGroupsCommand
} from "@aws-sdk/client-docdb";
import { EC2Client, DescribeNetworkAclsCommand, DescribeSubnetsCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDocDBSubnetGroupAcls from "./check-docdb-subnet-group-acls";

const mockDocDBClient = mockClient(DocDBClient);
const mockEC2Client = mockClient(EC2Client);

const mockCluster = {
	DBClusterIdentifier: "test-cluster-1",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster-1",
	DBSubnetGroup: "subnet-group-1"
};

const mockSubnetGroup = {
	DBSubnetGroups: [
		{
			Subnets: [{ SubnetIdentifier: "subnet-1" }, { SubnetIdentifier: "subnet-2" }]
		}
	]
};

const mockSubnets = {
	Subnets: [
		{ SubnetId: "subnet-1", VpcId: "vpc-1" },
		{ SubnetId: "subnet-2", VpcId: "vpc-1" }
	]
};

const mockNetworkAcls = {
	NetworkAcls: [
		{
			Associations: [{ SubnetId: "subnet-1" }, { SubnetId: "subnet-2" }]
		}
	]
};

describe("checkDocDBSubnetGroupAcls", () => {
	beforeEach(() => {
		mockDocDBClient.reset();
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when clusters have proper VPC and ACL configuration", async () => {
			mockDocDBClient
				.on(DescribeDBClustersCommand)
				.resolves({ DBClusters: [mockCluster] })
				.on(DescribeDBSubnetGroupsCommand)
				.resolves(mockSubnetGroup);

			mockEC2Client
				.on(DescribeSubnetsCommand)
				.resolves(mockSubnets)
				.on(DescribeNetworkAclsCommand)
				.resolves(mockNetworkAcls);

			const result = await checkDocDBSubnetGroupAcls.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-cluster-1");
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [] });

			const result = await checkDocDBSubnetGroupAcls.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No DocumentDB clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when subnets lack proper ACL configuration", async () => {
			mockDocDBClient
				.on(DescribeDBClustersCommand)
				.resolves({ DBClusters: [mockCluster] })
				.on(DescribeDBSubnetGroupsCommand)
				.resolves(mockSubnetGroup);

			mockEC2Client
				.on(DescribeSubnetsCommand)
				.resolves(mockSubnets)
				.on(DescribeNetworkAclsCommand)
				.resolves({ NetworkAcls: [] }); // No ACLs configured

			const result = await checkDocDBSubnetGroupAcls.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("not properly configured");
		});

		it("should return FAIL when subnet group has no subnets", async () => {
			mockDocDBClient
				.on(DescribeDBClustersCommand)
				.resolves({ DBClusters: [mockCluster] })
				.on(DescribeDBSubnetGroupsCommand)
				.resolves({ DBSubnetGroups: [{ Subnets: [] }] });

			const result = await checkDocDBSubnetGroupAcls.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No subnets found in the subnet group");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when DescribeDBClusters fails", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).rejects(new Error("API Error"));

			const result = await checkDocDBSubnetGroupAcls.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking DocumentDB clusters");
		});

		it("should return ERROR when cluster is missing required information", async () => {
			mockDocDBClient
				.on(DescribeDBClustersCommand)
				.resolves({ DBClusters: [{ DBClusterIdentifier: "test-cluster" }] }); // Missing DBSubnetGroup

			const result = await checkDocDBSubnetGroupAcls.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("missing identifier or subnet group");
		});

		it("should handle subnet configuration check errors", async () => {
			mockDocDBClient
				.on(DescribeDBClustersCommand)
				.resolves({ DBClusters: [mockCluster] })
				.on(DescribeDBSubnetGroupsCommand)
				.rejects(new Error("Subnet group error"));

			const result = await checkDocDBSubnetGroupAcls.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking subnet configuration");
		});
	});
});
