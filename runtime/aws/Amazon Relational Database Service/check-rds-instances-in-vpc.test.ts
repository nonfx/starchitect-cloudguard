//@ts-nocheck
import { RDSClient, DescribeDBInstancesCommand, type DBInstance } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsInstancesInVpc from "./check-rds-instances-in-vpc";

const mockRdsClient = mockClient(RDSClient);

const mockRdsInstanceInVpc: DBInstance = {
	DBInstanceIdentifier: "db-in-vpc",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:db-in-vpc",
	DBSubnetGroup: {
		VpcId: "vpc-12345"
	},
	VpcSecurityGroups: [{ VpcSecurityGroupId: "sg-12345" }]
};

const mockRdsInstanceNotInVpc: DBInstance = {
	DBInstanceIdentifier: "db-not-in-vpc",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:db-not-in-vpc",
	DBSubnetGroup: null,
	VpcSecurityGroups: []
};

describe("checkRdsInstancesInVpc", () => {
	beforeEach(() => {
		mockRdsClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS when RDS instance is in VPC", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockRdsInstanceInVpc]
			});

			const result = await checkRdsInstancesInVpc.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("db-in-vpc");
			expect(result.checks[0]?.resourceArn).toBe(mockRdsInstanceInVpc.DBInstanceArn);
		});

		test("should handle multiple compliant instances", async () => {
			const secondInstance: DBInstance = {
				...mockRdsInstanceInVpc,
				DBInstanceIdentifier: "db-in-vpc-2",
				DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:db-in-vpc-2"
			};

			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockRdsInstanceInVpc, secondInstance]
			});

			const result = await checkRdsInstancesInVpc.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when RDS instance is not in VPC", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockRdsInstanceNotInVpc]
			});

			const result = await checkRdsInstancesInVpc.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe("RDS instance is not deployed in a VPC");
		});

		test("should handle mixed compliance scenarios", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockRdsInstanceInVpc, mockRdsInstanceNotInVpc]
			});

			const result = await checkRdsInstancesInVpc.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases and Error Handling", () => {
		test("should return NOTAPPLICABLE when no instances exist", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: []
			});

			const result = await checkRdsInstancesInVpc.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS instances found in the region");
		});

		test("should return ERROR when API call fails", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).rejects(new Error("API Error"));

			const result = await checkRdsInstancesInVpc.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS instances");
		});

		test("should handle pagination", async () => {
			mockRdsClient
				.on(DescribeDBInstancesCommand)
				.resolvesOnce({
					DBInstances: [mockRdsInstanceInVpc],
					Marker: "token1"
				})
				.resolvesOnce({
					DBInstances: [mockRdsInstanceNotInVpc]
				});

			const result = await checkRdsInstancesInVpc.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});

		test("should handle missing DBInstanceArn", async () => {
			const instanceWithoutArn: DBInstance = {
				...mockRdsInstanceInVpc,
				DBInstanceArn: undefined
			};
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [instanceWithoutArn]
			});

			const result = await checkRdsInstancesInVpc.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Instance ARN not found");
		});
	});
});
