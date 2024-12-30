//@ts-nocheck
import { RDSClient, DescribeDBInstancesCommand, type DBInstance } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";

import checkRdsBackupEnabled from "./check-rds-backup-enabled";

const mockRdsClient = mockClient(RDSClient);

const mockCompliantInstance: DBInstance = {
	DBInstanceIdentifier: "test-db-1",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:test-db-1",
	BackupRetentionPeriod: 7
};

const mockNonCompliantInstance: DBInstance = {
	DBInstanceIdentifier: "test-db-2",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:test-db-2",
	BackupRetentionPeriod: 0
};

describe("checkRdsBackupEnabled", () => {
	beforeEach(() => {
		mockRdsClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS when backup retention period is greater than 0", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockCompliantInstance]
			});

			const result = await checkRdsBackupEnabled.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-db-1");
			expect(result.checks[0]?.resourceArn).toBe(mockCompliantInstance.DBInstanceArn);
		});

		test("should handle multiple compliant instances", async () => {
			const multipleInstances: DBInstance[] = [
				{ ...mockCompliantInstance },
				{
					...mockCompliantInstance,
					DBInstanceIdentifier: "test-db-3",
					BackupRetentionPeriod: 14
				}
			];

			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: multipleInstances
			});

			const result = await checkRdsBackupEnabled.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when backup retention period is 0", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockNonCompliantInstance]
			});

			const result = await checkRdsBackupEnabled.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("backup retention period of 0 days");
		});

		test("should handle mixed compliance scenarios", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockCompliantInstance, mockNonCompliantInstance]
			});

			const result = await checkRdsBackupEnabled.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});

		test("should handle instances without identifiers", async () => {
			const incompleteInstance: DBInstance = {
				BackupRetentionPeriod: 7
			};

			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [incompleteInstance]
			});

			const result = await checkRdsBackupEnabled.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("without identifier or ARN");
		});
	});

	describe("Edge Cases and Error Handling", () => {
		test("should return NOTAPPLICABLE when no instances exist", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: []
			});

			const result = await checkRdsBackupEnabled.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS instances found in the region");
		});

		test("should return ERROR when API call fails", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).rejects(new Error("API Error"));

			const result = await checkRdsBackupEnabled.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS instances");
		});

		test("should handle undefined DBInstances in response", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({});

			const result = await checkRdsBackupEnabled.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
