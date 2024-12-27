//@ts-nocheck
import { RDSClient, DescribeDBInstancesCommand, type DBInstance } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsMonitoringAndLoggingCompliance from "./check-rds-monitoring-logging";

const mockRDSClient = mockClient(RDSClient);

const mockCompliantInstance: DBInstance = {
	DBInstanceIdentifier: "compliant-db",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:compliant-db",
	MonitoringInterval: 60,
	MonitoringRoleArn: "arn:aws:iam::123456789012:role/monitoring-role",
	EnabledCloudwatchLogsExports: ["error", "general", "audit"]
};

const mockNonCompliantInstance: DBInstance = {
	DBInstanceIdentifier: "non-compliant-db",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:non-compliant-db",
	MonitoringInterval: 0,
	EnabledCloudwatchLogsExports: []
};

const mockPartiallyCompliantInstance: DBInstance = {
	DBInstanceIdentifier: "partial-compliant-db",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:partial-compliant-db",
	MonitoringInterval: 60,
	MonitoringRoleArn: "arn:aws:iam::123456789012:role/monitoring-role",
	EnabledCloudwatchLogsExports: []
};

describe("checkRdsMonitoringAndLoggingCompliance", () => {
	beforeEach(() => {
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS when monitoring and logging are enabled", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockCompliantInstance]
			});

			const result = await checkRdsMonitoringAndLoggingCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("compliant-db");
			expect(result.checks[0]?.resourceArn).toBe(mockCompliantInstance.DBInstanceArn);
		});

		test("should return NOTAPPLICABLE when no RDS instances exist", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: []
			});

			const result = await checkRdsMonitoringAndLoggingCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS instances found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when both monitoring and logging are disabled", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockNonCompliantInstance]
			});

			const result = await checkRdsMonitoringAndLoggingCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"RDS instance does not have monitoring and logging enabled"
			);
		});

		test("should return FAIL when only monitoring is enabled", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockPartiallyCompliantInstance]
			});

			const result = await checkRdsMonitoringAndLoggingCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe("RDS instance does not have logging enabled");
		});

		test("should handle multiple instances with mixed compliance", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [
					mockCompliantInstance,
					mockNonCompliantInstance,
					mockPartiallyCompliantInstance
				]
			});

			const result = await checkRdsMonitoringAndLoggingCompliance.execute();
			expect(result.checks).toHaveLength(3);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[2]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		test("should return ERROR when API call fails", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).rejects(new Error("API Error"));

			const result = await checkRdsMonitoringAndLoggingCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking RDS instances: API Error");
		});

		test("should handle instances without identifiers", async () => {
			const incompleteInstance: DBInstance = {
				...mockCompliantInstance,
				DBInstanceIdentifier: undefined
			};

			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [incompleteInstance]
			});

			const result = await checkRdsMonitoringAndLoggingCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("RDS instance found without identifier");
		});
	});
});
