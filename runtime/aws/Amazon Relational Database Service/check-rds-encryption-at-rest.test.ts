//@ts-nocheck
import { RDSClient, DescribeDBInstancesCommand, type DBInstance } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsEncryptionAtRest from "./check-rds-encryption-at-rest";

const mockRdsClient = mockClient(RDSClient);

const mockEncryptedInstance: DBInstance = {
	DBInstanceIdentifier: "encrypted-db-1",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:encrypted-db-1",
	StorageEncrypted: true
};

const mockUnencryptedInstance: DBInstance = {
	DBInstanceIdentifier: "unencrypted-db-1",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:unencrypted-db-1",
	StorageEncrypted: false
};

describe("checkRdsEncryptionAtRest", () => {
	beforeEach(() => {
		mockRdsClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS for encrypted RDS instances", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockEncryptedInstance]
			});

			const result = await checkRdsEncryptionAtRest.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("encrypted-db-1");
			expect(result.checks[0]?.resourceArn).toBe(mockEncryptedInstance.DBInstanceArn);
		});

		test("should return NOTAPPLICABLE when no RDS instances exist", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: []
			});

			const result = await checkRdsEncryptionAtRest.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS instances found in the region");
		});

		test("should handle pagination correctly for multiple compliant instances", async () => {
			const secondInstance: DBInstance = {
				...mockEncryptedInstance,
				DBInstanceIdentifier: "encrypted-db-2"
			};

			mockRdsClient
				.on(DescribeDBInstancesCommand)
				.resolvesOnce({
					DBInstances: [mockEncryptedInstance],
					Marker: "nextPage"
				})
				.resolvesOnce({
					DBInstances: [secondInstance]
				});

			const result = await checkRdsEncryptionAtRest.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL for unencrypted RDS instances", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockUnencryptedInstance]
			});

			const result = await checkRdsEncryptionAtRest.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"RDS instance does not have encryption-at-rest enabled"
			);
		});

		test("should handle mixed encrypted and unencrypted instances", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockEncryptedInstance, mockUnencryptedInstance]
			});

			const result = await checkRdsEncryptionAtRest.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});

		test("should handle instances with missing identifiers", async () => {
			const incompleteInstance: DBInstance = {
				StorageEncrypted: true
			};

			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [incompleteInstance]
			});

			const result = await checkRdsEncryptionAtRest.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("RDS instance found without identifier or ARN");
		});
	});

	describe("Error Handling", () => {
		test("should return ERROR when API call fails", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).rejects(new Error("API Error"));

			const result = await checkRdsEncryptionAtRest.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS instances: API Error");
		});

		test("should handle non-Error exceptions", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).rejects("String error");

			const result = await checkRdsEncryptionAtRest.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS instances: String error");
		});
	});
});
