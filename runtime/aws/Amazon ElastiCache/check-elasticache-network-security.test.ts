// @ts-nocheck
import { ElastiCacheClient, DescribeCacheClustersCommand } from "@aws-sdk/client-elasticache";
import { EC2Client, DescribeSecurityGroupsCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkElastiCacheNetworkSecurity from "./check-elasticache-network-security";

const mockElastiCacheClient = mockClient(ElastiCacheClient);
const mockEC2Client = mockClient(EC2Client);

const mockCompliantCluster = {
	CacheClusterId: "test-cluster-1",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:cluster:test-cluster-1",
	CacheSubnetGroupName: "subnet-group-1",
	SecurityGroups: [{ SecurityGroupId: "sg-12345" }]
};

const mockNonCompliantCluster = {
	CacheClusterId: "test-cluster-2",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:cluster:test-cluster-2",
	SecurityGroups: []
};

const mockSecurityGroup = {
	GroupId: "sg-12345",
	IpPermissions: [{ FromPort: 6379, ToPort: 6379, IpProtocol: "tcp" }],
	IpPermissionsEgress: [{ FromPort: -1, ToPort: -1, IpProtocol: "-1" }]
};

describe("checkElastiCacheNetworkSecurity", () => {
	beforeEach(() => {
		mockElastiCacheClient.reset();
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for cluster with proper VPC and security group configuration", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [mockCompliantCluster]
			});
			mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [mockSecurityGroup]
			});

			const result = await checkElastiCacheNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-cluster-1");
		});

		it("should handle multiple compliant clusters", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [mockCompliantCluster, mockCompliantCluster]
			});
			mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [mockSecurityGroup]
			});

			const result = await checkElastiCacheNetworkSecurity.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for cluster not in VPC", async () => {
			const clusterNotInVpc = { ...mockCompliantCluster, CacheSubnetGroupName: undefined };
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [clusterNotInVpc]
			});

			const result = await checkElastiCacheNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("not in a VPC");
		});

		it("should return FAIL for cluster without security groups", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [mockNonCompliantCluster]
			});

			const result = await checkElastiCacheNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("ElastiCache cluster is not in a VPC");
		});

		it("should return FAIL for security groups without proper rules", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [mockCompliantCluster]
			});
			mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [{ GroupId: "sg-12345", IpPermissions: [] }]
			});

			const result = await checkElastiCacheNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("proper ingress/egress rules");
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: []
			});

			const result = await checkElastiCacheNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});

		it("should return ERROR when ElastiCache API call fails", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).rejects(new Error("API Error"));

			const result = await checkElastiCacheNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking ElastiCache clusters");
		});

		it("should return ERROR when EC2 API call fails", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [mockCompliantCluster]
			});
			mockEC2Client.on(DescribeSecurityGroupsCommand).rejects(new Error("EC2 API Error"));

			const result = await checkElastiCacheNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking cluster security");
		});
	});
});
