//@ts-nocheck
import { RDSClient, DescribeDBInstancesCommand, type DBInstance } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsCloudWatchLogsEnabled from "./check-rds-cloudwatch-logs";

const mockRDSClient = mockClient(RDSClient);

const createMockDBInstance = (params: {
	identifier: string;
	engine: string;
	enabledLogs?: string[];
	arn?: string;
}): DBInstance => ({
	DBInstanceIdentifier: params.identifier,
	DBInstanceArn: params.arn || `arn:aws:rds:us-east-1:123456789012:db:${params.identifier}`,
	Engine: params.engine,
	EnabledCloudwatchLogsExports: params.enabledLogs || []
});

describe("checkRdsCloudWatchLogsEnabled", () => {
	beforeEach(() => {
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS for PostgreSQL instance with all required logs enabled", async () => {
			const mockInstance = createMockDBInstance({
				identifier: "postgres-db",
				engine: "postgres",
				enabledLogs: ["postgresql"]
			});

			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockInstance]
			});

			const result = await checkRdsCloudWatchLogsEnabled.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("postgres-db");
		});

		test("should return PASS for MySQL instance with all required logs enabled", async () => {
			const mockInstance = createMockDBInstance({
				identifier: "mysql-db",
				engine: "mysql",
				enabledLogs: ["audit"]
			});

			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockInstance]
			});

			const result = await checkRdsCloudWatchLogsEnabled.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});

		test("should return NOTAPPLICABLE for unsupported engine", async () => {
			const mockInstance = createMockDBInstance({
				identifier: "custom-db",
				engine: "custom"
			});

			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockInstance]
			});

			const result = await checkRdsCloudWatchLogsEnabled.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when required logs are not enabled", async () => {
			const mockInstance = createMockDBInstance({
				identifier: "mysql-db",
				engine: "mysql",
				enabledLogs: ["error", "general"] // missing "audit" log
			});

			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockInstance]
			});

			const result = await checkRdsCloudWatchLogsEnabled.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("Required CloudWatch logs are not enabled");
		});

		test("should return FAIL when no logs are enabled", async () => {
			const mockInstance = createMockDBInstance({
				identifier: "oracle-db",
				engine: "oracle-ee",
				enabledLogs: []
			});

			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockInstance]
			});

			const result = await checkRdsCloudWatchLogsEnabled.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		test("should return NOTAPPLICABLE when no instances exist", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: []
			});

			const result = await checkRdsCloudWatchLogsEnabled.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS instances found in the region");
		});

		test("should return ERROR when API call fails", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).rejects(new Error("API Error"));

			const result = await checkRdsCloudWatchLogsEnabled.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS instances");
		});

		test("should handle pagination", async () => {
			const instance1 = createMockDBInstance({
				identifier: "db-1",
				engine: "postgres",
				enabledLogs: ["postgresql"]
			});
			const instance2 = createMockDBInstance({
				identifier: "db-2",
				engine: "mysql",
				enabledLogs: ["audit"]
			});

			mockRDSClient
				.on(DescribeDBInstancesCommand)
				.resolvesOnce({
					DBInstances: [instance1],
					Marker: "token1"
				})
				.resolvesOnce({
					DBInstances: [instance2]
				});

			const result = await checkRdsCloudWatchLogsEnabled.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.PASS);
		});
	});
});
