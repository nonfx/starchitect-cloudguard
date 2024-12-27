//@ts-nocheck
import { RDSClient, DescribeDBInstancesCommand, type DBInstance } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsEnhancedMonitoring from "./check-rds-enhanced-monitoring";

const mockRDSClient = mockClient(RDSClient);

const mockCompliantInstance: DBInstance = {
	DBInstanceIdentifier: "db-instance-1",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:db-instance-1",
	MonitoringInterval: 60,
	MonitoringRoleArn: "arn:aws:iam::123456789012:role/rds-monitoring-role"
};

const mockNonCompliantInstance: DBInstance = {
	DBInstanceIdentifier: "db-instance-2",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:db-instance-2",
	MonitoringInterval: 0,
	MonitoringRoleArn: ""
};

describe("checkRdsEnhancedMonitoring", () => {
	beforeEach(() => {
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS for instances with valid monitoring configuration", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockCompliantInstance]
			});

			const result = await checkRdsEnhancedMonitoring.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("db-instance-1");
			expect(result.checks[0]?.resourceArn).toBe(mockCompliantInstance.DBInstanceArn);
		});

		test("should handle multiple compliant instances", async () => {
			const secondInstance: DBInstance = {
				...mockCompliantInstance,
				DBInstanceIdentifier: "db-instance-3",
				DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:db-instance-3",
				MonitoringInterval: 30
			};

			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockCompliantInstance, secondInstance]
			});

			const result = await checkRdsEnhancedMonitoring.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL for instances without enhanced monitoring", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockNonCompliantInstance]
			});

			const result = await checkRdsEnhancedMonitoring.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("Invalid monitoring interval");
			expect(result.checks[0]?.message).toContain("Monitoring role ARN not configured");
		});

		test("should return FAIL for invalid monitoring interval", async () => {
			const invalidInstance: DBInstance = {
				...mockCompliantInstance,
				MonitoringInterval: 45 // Invalid interval
			};

			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [invalidInstance]
			});

			const result = await checkRdsEnhancedMonitoring.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("Invalid monitoring interval");
		});

		test("should handle mixed compliance scenarios", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockCompliantInstance, mockNonCompliantInstance]
			});

			const result = await checkRdsEnhancedMonitoring.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases and Error Handling", () => {
		test("should return NOTAPPLICABLE when no instances exist", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: []
			});

			const result = await checkRdsEnhancedMonitoring.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS instances found in the region");
		});

		test("should return ERROR when API call fails", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).rejects(new Error("API Error"));

			const result = await checkRdsEnhancedMonitoring.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS instances");
		});

		test("should handle pagination", async () => {
			mockRDSClient
				.on(DescribeDBInstancesCommand)
				.resolvesOnce({
					DBInstances: [mockCompliantInstance],
					Marker: "next-page"
				})
				.resolvesOnce({
					DBInstances: [mockNonCompliantInstance]
				});

			const result = await checkRdsEnhancedMonitoring.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
		});
	});
});
