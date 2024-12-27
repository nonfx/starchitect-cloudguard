import { RDSClient, DescribeDBInstancesCommand, type DBInstance } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsAutoMinorVersionUpgrade from "./check-rds-auto-minor-version-upgrade";

const mockRDSClient = mockClient(RDSClient);

const mockRDSInstance: DBInstance = {
	DBInstanceIdentifier: "test-db-1",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:test-db-1",
	AutoMinorVersionUpgrade: true
};

const mockRDSInstanceNoAutoUpgrade: DBInstance = {
	DBInstanceIdentifier: "test-db-2",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:test-db-2",
	AutoMinorVersionUpgrade: false
};

describe("checkRdsAutoMinorVersionUpgrade", () => {
	beforeEach(() => {
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS when Auto Minor Version Upgrade is enabled", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockRDSInstance]
			});

			const result = await checkRdsAutoMinorVersionUpgrade.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-db-1");
			expect(result.checks[0]?.resourceArn).toBe(mockRDSInstance.DBInstanceArn!);
		});

		test("should return NOTAPPLICABLE when no RDS instances exist", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: []
			});

			const result = await checkRdsAutoMinorVersionUpgrade.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS instances found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when Auto Minor Version Upgrade is disabled", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockRDSInstanceNoAutoUpgrade]
			});

			const result = await checkRdsAutoMinorVersionUpgrade.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"Auto Minor Version Upgrade is not enabled for this RDS instance"
			);
		});

		test("should handle mixed compliance states", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockRDSInstance, mockRDSInstanceNoAutoUpgrade]
			});

			const result = await checkRdsAutoMinorVersionUpgrade.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});

		test("should handle instances without identifiers", async () => {
			const incompleteInstance: DBInstance = {
				AutoMinorVersionUpgrade: true
			};

			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [incompleteInstance]
			});

			const result = await checkRdsAutoMinorVersionUpgrade.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("RDS instance found without identifier or ARN");
		});
	});

	describe("Error Handling", () => {
		test("should handle API errors", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).rejects(new Error("API Error"));

			const result = await checkRdsAutoMinorVersionUpgrade.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error listing RDS instances");
		});

		test("should handle pagination", async () => {
			mockRDSClient
				.on(DescribeDBInstancesCommand)
				.resolvesOnce({
					DBInstances: [mockRDSInstance],
					Marker: "token1"
				})
				.resolvesOnce({
					DBInstances: [mockRDSInstanceNoAutoUpgrade]
				});

			const result = await checkRdsAutoMinorVersionUpgrade.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});
	});
});
