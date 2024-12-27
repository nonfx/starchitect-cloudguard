import { RDSClient, DescribeDBInstancesCommand, type DBInstance } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkRdsAutomatedBackups from "./check-rds-automated-backups";

const mockRDSClient = mockClient(RDSClient);

const mockCompliantInstance: DBInstance = {
	DBInstanceIdentifier: "compliant-db",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:compliant-db",
	BackupRetentionPeriod: 7
};

const mockNonCompliantInstance: DBInstance = {
	DBInstanceIdentifier: "non-compliant-db",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:non-compliant-db",
	BackupRetentionPeriod: 3
};

const mockReadReplica: DBInstance = {
	DBInstanceIdentifier: "read-replica-db",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:read-replica-db",
	ReadReplicaSourceDBInstanceIdentifier: "source-db",
	BackupRetentionPeriod: 0
};

describe("checkRdsAutomatedBackups", () => {
	beforeEach(() => {
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS for instances with sufficient backup retention", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockCompliantInstance]
			});

			const result = await checkRdsAutomatedBackups.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("compliant-db");
			expect(result.checks[0]?.message).toBeUndefined();
		});

		test("should return NOTAPPLICABLE for read replicas", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockReadReplica]
			});

			const result = await checkRdsAutomatedBackups.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("Instance is a read replica");
		});

		test("should handle multiple compliant instances", async () => {
			const multipleCompliantInstances: DBInstance[] = [
				{
					...mockCompliantInstance,
					DBInstanceIdentifier: "compliant-db-1",
					BackupRetentionPeriod: 7
				},
				{
					...mockCompliantInstance,
					DBInstanceIdentifier: "compliant-db-2",
					BackupRetentionPeriod: 14
				}
			];

			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: multipleCompliantInstances
			});

			const result = await checkRdsAutomatedBackups.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL for instances with insufficient backup retention", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockNonCompliantInstance]
			});

			const result = await checkRdsAutomatedBackups.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain(
				"retention period (3 days) is less than required 7 days"
			);
		});

		test("should return FAIL for instances with disabled backups", async () => {
			const disabledBackupsInstance: DBInstance = {
				...mockNonCompliantInstance,
				BackupRetentionPeriod: 0
			};

			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [disabledBackupsInstance]
			});

			const result = await checkRdsAutomatedBackups.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("retention period (0 days)");
		});

		test("should handle mixed compliance scenarios", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockCompliantInstance, mockNonCompliantInstance, mockReadReplica]
			});

			const result = await checkRdsAutomatedBackups.execute("us-east-1");
			expect(result.checks).toHaveLength(3);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[2]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});

	describe("Edge Cases and Error Handling", () => {
		test("should return NOTAPPLICABLE when no instances exist", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: []
			});

			const result = await checkRdsAutomatedBackups.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS instances found in the region");
		});

		test("should handle pagination correctly", async () => {
			mockRDSClient
				.on(DescribeDBInstancesCommand)
				.resolvesOnce({
					DBInstances: [mockCompliantInstance],
					Marker: "next-page"
				})
				.resolvesOnce({
					DBInstances: [mockNonCompliantInstance]
				});

			const result = await checkRdsAutomatedBackups.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
		});

		test("should return ERROR when API call fails", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).rejects(new Error("API Error"));

			const result = await checkRdsAutomatedBackups.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS instances: API Error");
		});
	});
});
