//@ts-nocheck
import { RDSClient, DescribeDBInstancesCommand, type DBInstance } from "@aws-sdk/client-rds";
import {
	EC2Client,
	DescribeSecurityGroupsCommand,
	type SecurityGroup,
	type IpPermission
} from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";

import checkRdsSecurityGroupsConfigured from "./check-rds-security-groups-configured";

const mockRdsClient = mockClient(RDSClient);
const mockEc2Client = mockClient(EC2Client);

const mockRdsInstance: DBInstance = {
	DBInstanceIdentifier: "test-db-1",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:test-db-1",
	VpcSecurityGroups: [{ VpcSecurityGroupId: "sg-12345678" }]
};

const mockSecurityGroup: SecurityGroup = {
	GroupId: "sg-12345678",
	IpPermissions: [
		{
			IpProtocol: "tcp",
			FromPort: 3306,
			ToPort: 3306
		} as IpPermission
	],
	IpPermissionsEgress: [
		{
			IpProtocol: "-1",
			FromPort: -1,
			ToPort: -1
		} as IpPermission
	]
};

describe("checkRdsSecurityGroupsConfigured", () => {
	beforeEach(() => {
		mockRdsClient.reset();
		mockEc2Client.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS when RDS instance has properly configured security groups", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockRdsInstance]
			});
			mockEc2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [mockSecurityGroup]
			});

			const result = await checkRdsSecurityGroupsConfigured.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-db-1");
		});

		test("should handle multiple RDS instances with valid configurations", async () => {
			const secondInstance: DBInstance = {
				...mockRdsInstance,
				DBInstanceIdentifier: "test-db-2",
				DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:test-db-2"
			};

			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockRdsInstance, secondInstance]
			});
			mockEc2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [mockSecurityGroup]
			});

			const result = await checkRdsSecurityGroupsConfigured.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when RDS instance has no security groups", async () => {
			const instanceWithoutSG: DBInstance = {
				...mockRdsInstance,
				VpcSecurityGroups: []
			};

			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [instanceWithoutSG]
			});

			const result = await checkRdsSecurityGroupsConfigured.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"RDS instance does not have any security groups configured"
			);
		});

		test("should return FAIL when security group has no inbound rules", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockRdsInstance]
			});
			mockEc2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [
					{
						...mockSecurityGroup,
						IpPermissions: []
					}
				]
			});

			const result = await checkRdsSecurityGroupsConfigured.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("has no inbound rules");
		});

		test("should return FAIL when security group has no outbound rules", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockRdsInstance]
			});
			mockEc2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [
					{
						...mockSecurityGroup,
						IpPermissionsEgress: []
					}
				]
			});

			const result = await checkRdsSecurityGroupsConfigured.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("has no outbound rules");
		});
	});

	describe("Error Handling", () => {
		test("should return NOTAPPLICABLE when no RDS instances exist", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: []
			});

			const result = await checkRdsSecurityGroupsConfigured.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});

		test("should return ERROR when RDS API call fails", async () => {
			mockRdsClient
				.on(DescribeDBInstancesCommand)
				.rejects(new Error("Failed to describe DB instances"));

			const result = await checkRdsSecurityGroupsConfigured.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Failed to describe DB instances");
		});

		test("should return ERROR when EC2 security group check fails", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockRdsInstance]
			});
			mockEc2Client
				.on(DescribeSecurityGroupsCommand)
				.rejects(new Error("Failed to describe security groups"));

			const result = await checkRdsSecurityGroupsConfigured.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking security groups");
		});
	});
});
