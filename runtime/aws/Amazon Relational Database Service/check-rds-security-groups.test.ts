//@ts-nocheck
import {
	RDSClient,
	DescribeDBClustersCommand,
	DescribeDBInstancesCommand,
	type DBCluster,
	type DBInstance
} from "@aws-sdk/client-rds";
import {
	EC2Client,
	DescribeSecurityGroupsCommand,
	type SecurityGroup,
	type IpPermission
} from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsSecurityGroups from "./check-rds-security-groups";

const mockRdsClient = mockClient(RDSClient);
const mockEc2Client = mockClient(EC2Client);

const mockCluster: DBCluster = {
	DBClusterIdentifier: "test-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster",
	VpcSecurityGroups: [{ VpcSecurityGroupId: "sg-12345" }]
};

const mockInstance: DBInstance = {
	DBInstanceIdentifier: "test-instance",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:test-instance",
	VpcSecurityGroups: [{ VpcSecurityGroupId: "sg-67890" }]
};

const mockSecurityGroup: SecurityGroup = {
	GroupId: "sg-12345",
	IpPermissions: [{ FromPort: 3306 } as IpPermission],
	IpPermissionsEgress: [{ FromPort: -1 } as IpPermission]
};

describe("checkRdsSecurityGroups", () => {
	beforeEach(() => {
		mockRdsClient.reset();
		mockEc2Client.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS for cluster with properly configured security groups", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [mockCluster] });
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] });
			mockEc2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [mockSecurityGroup]
			});

			const result = await checkRdsSecurityGroups.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-cluster");
		});

		test("should return PASS for instance with properly configured security groups", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [] });
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({ DBInstances: [mockInstance] });
			mockEc2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [mockSecurityGroup]
			});

			const result = await checkRdsSecurityGroups.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-instance");
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL for cluster without security groups", async () => {
			const clusterNoSG: DBCluster = { ...mockCluster, VpcSecurityGroups: [] };
			mockRdsClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [clusterNoSG] });
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] });

			const result = await checkRdsSecurityGroups.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe("RDS cluster has no security groups attached");
		});

		test("should return FAIL for security group without rules", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [mockCluster] });
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] });
			mockEc2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [
					{
						GroupId: "sg-12345",
						IpPermissions: [],
						IpPermissionsEgress: []
					} as SecurityGroup
				]
			});

			const result = await checkRdsSecurityGroups.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("missing inbound rules");
		});
	});

	describe("Edge Cases", () => {
		test("should return NOTAPPLICABLE when no RDS resources exist", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [] });
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] });

			const result = await checkRdsSecurityGroups.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS clusters or instances found in the region");
		});

		test("should return ERROR when RDS API call fails", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).rejects(new Error("API Error"));

			const result = await checkRdsSecurityGroups.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS resources");
		});

		test("should return ERROR when EC2 security group check fails", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [mockCluster] });
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] });
			mockEc2Client.on(DescribeSecurityGroupsCommand).rejects(new Error("Security Group Error"));

			const result = await checkRdsSecurityGroups.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking security group");
		});
	});

	describe("Mixed Scenarios", () => {
		test("should handle mix of compliant and non-compliant resources", async () => {
			const clusterNoSG: DBCluster = { ...mockCluster, VpcSecurityGroups: [] };
			mockRdsClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCluster, clusterNoSG]
			});
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] });
			mockEc2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [mockSecurityGroup]
			});

			const result = await checkRdsSecurityGroups.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});
	});
});
