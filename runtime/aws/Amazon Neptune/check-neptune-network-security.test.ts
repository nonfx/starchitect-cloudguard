// @ts-nocheck
import { NeptuneClient, DescribeDBClustersCommand } from "@aws-sdk/client-neptune";
import { EC2Client, DescribeSecurityGroupsCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkNeptuneNetworkSecurity from "./check-neptune-network-security";

const mockNeptuneClient = mockClient(NeptuneClient);
const mockEC2Client = mockClient(EC2Client);

const mockCluster = {
	DBClusterIdentifier: "test-cluster-1",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster-1",
	VpcSecurityGroups: [{ VpcSecurityGroupId: "sg-12345678" }]
};

const mockSecurityGroup = {
	GroupId: "sg-12345678",
	IpPermissions: [{ FromPort: 8182, ToPort: 8182, IpProtocol: "tcp" }],
	IpPermissionsEgress: [{ FromPort: -1, ToPort: -1, IpProtocol: "-1" }]
};

describe("checkNeptuneNetworkSecurity", () => {
	beforeEach(() => {
		mockNeptuneClient.reset();
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Neptune cluster has proper security configuration", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCluster]
			});
			mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [mockSecurityGroup]
			});

			const result = await checkNeptuneNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-cluster-1");
		});

		it("should return NOTAPPLICABLE when no Neptune clusters exist", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkNeptuneNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Neptune clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when cluster has no VPC security groups", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [
					{
						...mockCluster,
						VpcSecurityGroups: []
					}
				]
			});

			const result = await checkNeptuneNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("not configured with VPC security groups");
		});

		it("should return FAIL when security groups lack proper rules", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCluster]
			});
			mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [
					{
						GroupId: "sg-12345678",
						IpPermissions: [],
						IpPermissionsEgress: []
					}
				]
			});

			const result = await checkNeptuneNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("do not have proper inbound/outbound rules");
		});

		it("should handle multiple clusters with mixed compliance", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [
					mockCluster,
					{
						...mockCluster,
						DBClusterIdentifier: "test-cluster-2",
						VpcSecurityGroups: []
					}
				]
			});
			mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [mockSecurityGroup]
			});

			const result = await checkNeptuneNetworkSecurity.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when Neptune API call fails", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).rejects(new Error("API Error"));

			const result = await checkNeptuneNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Neptune clusters");
		});

		it("should return ERROR when EC2 API call fails", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCluster]
			});
			mockEC2Client.on(DescribeSecurityGroupsCommand).rejects(new Error("Security Group Error"));

			const result = await checkNeptuneNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking cluster security");
		});

		it("should handle clusters without identifiers", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [{ ...mockCluster, DBClusterIdentifier: undefined }]
			});

			const result = await checkNeptuneNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without identifier");
		});
	});
});
