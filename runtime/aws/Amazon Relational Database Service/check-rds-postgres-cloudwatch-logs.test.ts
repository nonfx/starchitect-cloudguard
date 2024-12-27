//@ts-nocheck
import { RDSClient, DescribeDBInstancesCommand, type DBInstance } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsPostgresCloudWatchLogs from "./check-rds-postgres-cloudwatch-logs";

const mockRDSClient = mockClient(RDSClient);

const mockPostgresInstance: DBInstance = {
	DBInstanceIdentifier: "postgres-db-1",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:postgres-db-1",
	Engine: "postgres",
	EnabledCloudwatchLogsExports: ["postgresql"]
};

const mockPostgresInstanceNoLogs: DBInstance = {
	DBInstanceIdentifier: "postgres-db-2",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:postgres-db-2",
	Engine: "postgres",
	EnabledCloudwatchLogsExports: []
};

const mockMySQLInstance: DBInstance = {
	DBInstanceIdentifier: "mysql-db-1",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:mysql-db-1",
	Engine: "mysql",
	EnabledCloudwatchLogsExports: []
};

describe("checkRdsPostgresCloudWatchLogs", () => {
	beforeEach(() => {
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS when PostgreSQL instance has CloudWatch logs enabled", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockPostgresInstance]
			});

			const result = await checkRdsPostgresCloudWatchLogs.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("postgres-db-1");
			expect(result.checks[0]?.resourceArn).toBe(mockPostgresInstance.DBInstanceArn);
		});

		test("should skip non-PostgreSQL instances", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockMySQLInstance]
			});

			const result = await checkRdsPostgresCloudWatchLogs.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No PostgreSQL instances found in the region");
		});

		test("should return NOTAPPLICABLE when no RDS instances exist", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: []
			});

			const result = await checkRdsPostgresCloudWatchLogs.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS instances found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when PostgreSQL instance has CloudWatch logs disabled", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockPostgresInstanceNoLogs]
			});

			const result = await checkRdsPostgresCloudWatchLogs.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"PostgreSQL logs are not fully enabled. Required logs: postgresql, upgrade. Enabled logs: "
			);
		});

		test("should handle mixed compliance scenarios", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockPostgresInstance, mockPostgresInstanceNoLogs, mockMySQLInstance]
			});

			const result = await checkRdsPostgresCloudWatchLogs.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});

		test("should handle instance without identifier", async () => {
			const incompleteInstance: DBInstance = {
				...mockPostgresInstance,
				DBInstanceIdentifier: undefined
			};

			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [incompleteInstance]
			});

			const result = await checkRdsPostgresCloudWatchLogs.execute();
			expect(result.checks[0]?.resourceName).toBe("Unknown Instance");
		});
	});

	describe("Error Handling", () => {
		test("should return ERROR when API call fails", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).rejects(new Error("API Error"));

			const result = await checkRdsPostgresCloudWatchLogs.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS instances: API Error");
		});

		test("should handle pagination", async () => {
			mockRDSClient
				.on(DescribeDBInstancesCommand)
				.resolvesOnce({
					DBInstances: [mockPostgresInstance],
					Marker: "token1"
				})
				.resolvesOnce({
					DBInstances: [mockPostgresInstanceNoLogs]
				});

			const result = await checkRdsPostgresCloudWatchLogs.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});
	});
});
