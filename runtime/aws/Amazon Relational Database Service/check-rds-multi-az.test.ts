import { RDSClient, DescribeDBInstancesCommand, type DBInstance } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsMultiAzCompliance from "./check-rds-multi-az";

const mockRdsClient = mockClient(RDSClient);

const mockMultiAzInstance: DBInstance = {
	DBInstanceIdentifier: "db-multi-az",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:db-multi-az",
	MultiAZ: true
};

const mockSingleAzInstance: DBInstance = {
	DBInstanceIdentifier: "db-single-az",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:db-single-az",
	MultiAZ: false
};

describe("checkRdsMultiAzCompliance", () => {
	beforeEach(() => {
		mockRdsClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS for RDS instances with Multi-AZ enabled", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockMultiAzInstance]
			});

			const result = await checkRdsMultiAzCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("db-multi-az");
			expect(result.checks[0]?.resourceArn).toBe(mockMultiAzInstance.DBInstanceArn);
		});

		test("should handle multiple compliant instances", async () => {
			const secondInstance: DBInstance = {
				...mockMultiAzInstance,
				DBInstanceIdentifier: "db-multi-az-2",
				DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:db-multi-az-2"
			};

			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockMultiAzInstance, secondInstance]
			});

			const result = await checkRdsMultiAzCompliance.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL for RDS instances without Multi-AZ", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockSingleAzInstance]
			});

			const result = await checkRdsMultiAzCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"RDS DB instance is not configured with multiple Availability Zones"
			);
		});

		test("should handle mixed compliance scenarios", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockMultiAzInstance, mockSingleAzInstance]
			});

			const result = await checkRdsMultiAzCompliance.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});

		test("should handle instances without ARN", async () => {
			const incompleteInstance: DBInstance = {
				DBInstanceIdentifier: "no-arn-instance",
				MultiAZ: true
			};

			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [incompleteInstance]
			});

			const result = await checkRdsMultiAzCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Instance ARN not found");
		});
	});

	describe("Edge Cases and Error Handling", () => {
		test("should return NOTAPPLICABLE when no instances exist", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: []
			});

			const result = await checkRdsMultiAzCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS DB instances found in the region");
		});

		test("should handle API errors", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).rejects(new Error("API Error"));

			const result = await checkRdsMultiAzCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS instances");
		});

		test("should handle pagination", async () => {
			mockRdsClient
				.on(DescribeDBInstancesCommand)
				.resolvesOnce({
					DBInstances: [mockMultiAzInstance],
					Marker: "next-page"
				})
				.resolvesOnce({
					DBInstances: [mockSingleAzInstance]
				});

			const result = await checkRdsMultiAzCompliance.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});
	});
});
