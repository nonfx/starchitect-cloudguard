//@ts-nocheck
import { RDSClient, DescribeDBInstancesCommand, type DBInstance } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsTagCopyCompliance from "./check-rds-tag-copy-compliance";

const mockRdsClient = mockClient(RDSClient);

const mockCompliantInstance: DBInstance = {
	DBInstanceIdentifier: "compliant-db",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:compliant-db",
	CopyTagsToSnapshot: true
};

const mockNonCompliantInstance: DBInstance = {
	DBInstanceIdentifier: "non-compliant-db",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:non-compliant-db",
	CopyTagsToSnapshot: false
};

describe("checkRdsTagCopyCompliance", () => {
	beforeEach(() => {
		mockRdsClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS when RDS instance has tag copying enabled", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockCompliantInstance]
			});

			const result = await checkRdsTagCopyCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("compliant-db");
			expect(result.checks[0]?.resourceArn).toBe(mockCompliantInstance.DBInstanceArn);
		});

		test("should handle multiple compliant instances", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockCompliantInstance, mockCompliantInstance]
			});

			const result = await checkRdsTagCopyCompliance.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when RDS instance has tag copying disabled", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockNonCompliantInstance]
			});

			const result = await checkRdsTagCopyCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"RDS instance is not configured to copy tags to snapshots"
			);
		});

		test("should handle mixed compliance scenarios", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockCompliantInstance, mockNonCompliantInstance]
			});

			const result = await checkRdsTagCopyCompliance.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});

		test("should handle instances without ARN", async () => {
			const instanceWithoutArn: DBInstance = {
				...mockCompliantInstance,
				DBInstanceArn: undefined
			};
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [instanceWithoutArn]
			});

			const result = await checkRdsTagCopyCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Instance ARN not found");
		});
	});

	describe("Edge Cases and Error Handling", () => {
		test("should return NOTAPPLICABLE when no instances exist", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: []
			});

			const result = await checkRdsTagCopyCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS instances found in the region");
		});

		test("should handle API errors", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).rejects(new Error("API Error"));

			const result = await checkRdsTagCopyCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS instances: API Error");
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

			const result = await checkRdsTagCopyCompliance.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});
	});
});
