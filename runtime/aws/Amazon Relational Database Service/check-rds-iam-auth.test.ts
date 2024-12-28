//@ts-nocheck
import { RDSClient, DescribeDBInstancesCommand, type DBInstance } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsIamAuthCompliance from "./check-rds-iam-auth";

const mockRDSClient = mockClient(RDSClient);

const mockRdsInstance = (params: {
	identifier: string;
	engine: string;
	iamAuthEnabled: boolean;
}): DBInstance => ({
	DBInstanceIdentifier: params.identifier,
	DBInstanceArn: `arn:aws:rds:us-east-1:123456789012:db:${params.identifier}`,
	Engine: params.engine,
	IAMDatabaseAuthenticationEnabled: params.iamAuthEnabled
});

describe("checkRdsIamAuthCompliance", () => {
	beforeEach(() => {
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS for instances with IAM authentication enabled", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [
					mockRdsInstance({
						identifier: "db-1",
						engine: "mysql",
						iamAuthEnabled: true
					})
				]
			});

			const result = await checkRdsIamAuthCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("db-1");
		});

		test("should handle multiple compliant instances", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [
					mockRdsInstance({
						identifier: "db-1",
						engine: "postgres",
						iamAuthEnabled: true
					}),
					mockRdsInstance({
						identifier: "db-2",
						engine: "aurora-mysql",
						iamAuthEnabled: true
					})
				]
			});

			const result = await checkRdsIamAuthCompliance.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL for instances without IAM authentication", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [
					mockRdsInstance({
						identifier: "db-1",
						engine: "mysql",
						iamAuthEnabled: false
					})
				]
			});

			const result = await checkRdsIamAuthCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe("IAM database authentication is not enabled");
		});

		test("should return NOTAPPLICABLE for unsupported engines", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [
					mockRdsInstance({
						identifier: "db-1",
						engine: "oracle",
						iamAuthEnabled: false
					})
				]
			});

			const result = await checkRdsIamAuthCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toContain("does not support IAM authentication");
		});

		test("should handle mixed compliance scenarios", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [
					mockRdsInstance({
						identifier: "db-1",
						engine: "mysql",
						iamAuthEnabled: true
					}),
					mockRdsInstance({
						identifier: "db-2",
						engine: "postgres",
						iamAuthEnabled: false
					}),
					mockRdsInstance({
						identifier: "db-3",
						engine: "oracle",
						iamAuthEnabled: false
					})
				]
			});

			const result = await checkRdsIamAuthCompliance.execute();
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

			const result = await checkRdsIamAuthCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS instances found in the region");
		});

		test("should handle pagination", async () => {
			mockRDSClient
				.on(DescribeDBInstancesCommand)
				.resolvesOnce({
					DBInstances: [
						mockRdsInstance({
							identifier: "db-1",
							engine: "mysql",
							iamAuthEnabled: true
						})
					],
					Marker: "next-page"
				})
				.resolvesOnce({
					DBInstances: [
						mockRdsInstance({
							identifier: "db-2",
							engine: "postgres",
							iamAuthEnabled: false
						})
					]
				});

			const result = await checkRdsIamAuthCompliance.execute();
			expect(result.checks).toHaveLength(2);
		});

		test("should return ERROR when API call fails", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).rejects(new Error("API Error"));

			const result = await checkRdsIamAuthCompliance.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS instances");
		});
	});
});
