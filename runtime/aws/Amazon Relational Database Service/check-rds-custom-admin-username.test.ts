//@ts-nocheck
import { RDSClient, DescribeDBInstancesCommand, type DBInstance } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsCustomAdminUsername from "./check-rds-custom-admin-username";

const mockRDSClient = mockClient(RDSClient);

const mockRdsInstance = (identifier: string, username: string): DBInstance => ({
	DBInstanceIdentifier: identifier,
	DBInstanceArn: `arn:aws:rds:us-east-1:123456789012:db:${identifier}`,
	MasterUsername: username
});

describe("checkRdsCustomAdminUsername", () => {
	beforeEach(() => {
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS when RDS instances use custom admin usernames", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [
					mockRdsInstance("custom-db-1", "customadmin"),
					mockRdsInstance("custom-db-2", "dbadmin123")
				]
			});

			const result = await checkRdsCustomAdminUsername.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.PASS);
		});

		test("should handle pagination correctly for compliant instances", async () => {
			mockRDSClient
				.on(DescribeDBInstancesCommand)
				.resolvesOnce({
					DBInstances: [mockRdsInstance("custom-db-1", "customadmin")],
					Marker: "nextpage"
				})
				.resolvesOnce({
					DBInstances: [mockRdsInstance("custom-db-2", "dbadmin123")]
				});

			const result = await checkRdsCustomAdminUsername.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when RDS instances use default admin usernames", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [
					mockRdsInstance("default-db-1", "admin"),
					mockRdsInstance("default-db-2", "postgres"),
					mockRdsInstance("default-db-3", "root")
				]
			});

			const result = await checkRdsCustomAdminUsername.execute();
			expect(result.checks).toHaveLength(3);
			expect(result.checks.every(check => check?.status === ComplianceStatus.FAIL)).toBe(true);
			expect(result.checks[0]?.message).toContain("uses default admin username");
		});

		test("should handle mixed compliance scenarios", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [
					mockRdsInstance("custom-db", "customadmin"),
					mockRdsInstance("default-db", "admin")
				]
			});

			const result = await checkRdsCustomAdminUsername.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		test("should return NOTAPPLICABLE when no RDS instances exist", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: []
			});

			const result = await checkRdsCustomAdminUsername.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS instances found in the region");
		});

		test("should return ERROR when API call fails", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).rejects(new Error("API Error"));

			const result = await checkRdsCustomAdminUsername.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS instances");
		});

		test("should handle instances with missing identifiers", async () => {
			const incompleteInstance: DBInstance = {
				MasterUsername: "admin"
			};

			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [incompleteInstance]
			});

			const result = await checkRdsCustomAdminUsername.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("RDS instance found without identifier or ARN");
		});

		test("should handle instances with missing master username", async () => {
			const instanceWithoutUsername: DBInstance = {
				DBInstanceIdentifier: "db-no-username",
				DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:db-no-username"
			};

			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [instanceWithoutUsername]
			});

			const result = await checkRdsCustomAdminUsername.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Unable to determine master username");
		});
	});
});
