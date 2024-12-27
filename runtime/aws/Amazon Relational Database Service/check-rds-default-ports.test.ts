//@ts-nocheck
import { RDSClient, DescribeDBInstancesCommand, type DBInstance } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsDefaultPorts from "./check-rds-default-ports";

const mockRdsClient = mockClient(RDSClient);

const mockCompliantInstance: DBInstance = {
	DBInstanceIdentifier: "custom-port-instance",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:custom-port-instance",
	Engine: "mysql",
	Endpoint: {
		Port: 3307
	}
};

const mockNonCompliantInstance: DBInstance = {
	DBInstanceIdentifier: "default-port-instance",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:default-port-instance",
	Engine: "mysql",
	Endpoint: {
		Port: 3306
	}
};

describe("checkRdsDefaultPorts", () => {
	beforeEach(() => {
		mockRdsClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS when RDS instance uses non-default port", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockCompliantInstance]
			});

			const result = await checkRdsDefaultPorts.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("custom-port-instance");
		});

		test("should return NOTAPPLICABLE when no RDS instances exist", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: []
			});

			const result = await checkRdsDefaultPorts.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS instances found in the region");
		});

		test("should handle multiple compliant instances", async () => {
			const multipleCompliant: DBInstance[] = [
				{ ...mockCompliantInstance },
				{
					DBInstanceIdentifier: "postgres-custom",
					DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:postgres-custom",
					Engine: "postgres",
					Endpoint: { Port: 5433 }
				}
			];

			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: multipleCompliant
			});

			const result = await checkRdsDefaultPorts.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when RDS instance uses default port", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockNonCompliantInstance]
			});

			const result = await checkRdsDefaultPorts.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("uses default port 3306");
		});

		test("should handle mixed compliance scenarios", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockCompliantInstance, mockNonCompliantInstance]
			});

			const result = await checkRdsDefaultPorts.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});

		test("should return ERROR for instances with missing information", async () => {
			const invalidInstance: DBInstance = {
				DBInstanceIdentifier: "invalid-instance",
				DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:invalid-instance",
				Engine: "mysql"
				// Missing Endpoint
			};

			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [invalidInstance]
			});

			const result = await checkRdsDefaultPorts.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("missing required information");
		});
	});

	describe("Error Handling", () => {
		test("should handle API errors gracefully", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).rejects(new Error("API Error"));

			const result = await checkRdsDefaultPorts.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS instances");
		});

		test("should handle pagination", async () => {
			mockRdsClient
				.on(DescribeDBInstancesCommand)
				.resolvesOnce({
					DBInstances: [mockCompliantInstance],
					Marker: "nextPage"
				})
				.resolvesOnce({
					DBInstances: [mockNonCompliantInstance]
				});

			const result = await checkRdsDefaultPorts.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});
	});
});
