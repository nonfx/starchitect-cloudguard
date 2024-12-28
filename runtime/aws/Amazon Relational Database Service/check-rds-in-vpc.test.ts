//@ts-nocheck
import {
	RDSClient,
	DescribeDBInstancesCommand,
	DescribeDBSubnetGroupsCommand,
	type DBInstance,
	type DBSubnetGroup
} from "@aws-sdk/client-rds";
import { EC2Client, DescribeVpcsCommand, type Vpc } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsInVpcCompliance from "./check-rds-in-vpc";

const mockRdsClient = mockClient(RDSClient);
const mockEc2Client = mockClient(EC2Client);

const mockRdsInstance: DBInstance = {
	DBInstanceIdentifier: "test-db-1",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:test-db-1",
	DBSubnetGroup: {
		DBSubnetGroupName: "test-subnet-group"
	}
};

const mockSubnetGroup: DBSubnetGroup = {
	DBSubnetGroupName: "test-subnet-group",
	DBSubnetGroupDescription: "Test subnet group",
	VpcId: "vpc-1",
	SubnetGroupStatus: "Complete",
	Subnets: [
		{ SubnetIdentifier: "subnet-1", SubnetStatus: "Active" },
		{ SubnetIdentifier: "subnet-2", SubnetStatus: "Active" }
	]
};

describe("checkRdsInVpcCompliance", () => {
	beforeEach(() => {
		mockRdsClient.reset();
		mockEc2Client.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS when RDS instance is properly configured in VPC", async () => {
			mockEc2Client.on(DescribeVpcsCommand).resolves({
				Vpcs: [{ VpcId: "vpc-1" } as Vpc]
			});
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockRdsInstance]
			});
			mockRdsClient.on(DescribeDBSubnetGroupsCommand).resolves({
				DBSubnetGroups: [mockSubnetGroup]
			});

			const result = await checkRdsInVpcCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-db-1");
		});

		test("should return NOTAPPLICABLE when no RDS instances exist", async () => {
			mockEc2Client.on(DescribeVpcsCommand).resolves({
				Vpcs: [{ VpcId: "vpc-1" } as Vpc]
			});
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: []
			});

			const result = await checkRdsInVpcCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS instances found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when no VPC exists", async () => {
			mockEc2Client.on(DescribeVpcsCommand).resolves({
				Vpcs: []
			});

			const result = await checkRdsInVpcCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("No VPC exists");
		});

		test("should return FAIL when RDS instance has no subnet group", async () => {
			mockEc2Client.on(DescribeVpcsCommand).resolves({
				Vpcs: [{ VpcId: "vpc-1" } as Vpc]
			});
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [
					{
						...mockRdsInstance,
						DBSubnetGroup: undefined
					}
				]
			});

			const result = await checkRdsInVpcCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("not deployed in a VPC");
		});

		test("should return FAIL when subnet group has no subnets", async () => {
			mockEc2Client.on(DescribeVpcsCommand).resolves({
				Vpcs: [{ VpcId: "vpc-1" } as Vpc]
			});
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockRdsInstance]
			});
			mockRdsClient.on(DescribeDBSubnetGroupsCommand).resolves({
				DBSubnetGroups: [
					{
						...mockSubnetGroup,
						Subnets: []
					}
				]
			});

			const result = await checkRdsInVpcCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("no associated subnets");
		});
	});

	describe("Error Handling", () => {
		test("should return ERROR when RDS API call fails", async () => {
			mockEc2Client.on(DescribeVpcsCommand).resolves({
				Vpcs: [{ VpcId: "vpc-1" } as Vpc]
			});
			mockRdsClient.on(DescribeDBInstancesCommand).rejects(new Error("API Error"));

			const result = await checkRdsInVpcCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS instances");
		});

		test("should return ERROR when subnet group check fails", async () => {
			mockEc2Client.on(DescribeVpcsCommand).resolves({
				Vpcs: [{ VpcId: "vpc-1" } as Vpc]
			});
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockRdsInstance]
			});
			mockRdsClient.on(DescribeDBSubnetGroupsCommand).rejects(new Error("Subnet Group Error"));

			const result = await checkRdsInVpcCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking subnet group");
		});
	});
});
