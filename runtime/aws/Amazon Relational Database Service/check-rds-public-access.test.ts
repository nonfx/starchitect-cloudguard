//@ts-nocheck
import { RDSClient, DescribeDBInstancesCommand, type DBInstance } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";

import checkRdsPublicAccess from "./check-rds-public-access";

const mockRdsClient = mockClient(RDSClient);

const mockPublicInstance: DBInstance = {
	DBInstanceIdentifier: "public-db-1",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:public-db-1",
	PubliclyAccessible: true
};

const mockPrivateInstance: DBInstance = {
	DBInstanceIdentifier: "private-db-1",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:private-db-1",
	PubliclyAccessible: false
};

describe("checkRdsPublicAccess", () => {
	beforeEach(() => {
		mockRdsClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS for private RDS instances", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockPrivateInstance]
			});

			const result = await checkRdsPublicAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("private-db-1");
			expect(result.checks[0]?.resourceArn).toBe(mockPrivateInstance.DBInstanceArn);
		});

		test("should return NOTAPPLICABLE when no RDS instances exist", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: []
			});

			const result = await checkRdsPublicAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS instances found in the region");
		});

		test("should handle multiple private instances", async () => {
			const secondInstance: DBInstance = {
				...mockPrivateInstance,
				DBInstanceIdentifier: "private-db-2",
				DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:private-db-2"
			};

			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockPrivateInstance, secondInstance]
			});

			const result = await checkRdsPublicAccess.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL for public RDS instances", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockPublicInstance]
			});

			const result = await checkRdsPublicAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe("RDS instance is publicly accessible");
		});

		test("should handle mixed public and private instances", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockPublicInstance, mockPrivateInstance]
			});

			const result = await checkRdsPublicAccess.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.PASS);
		});

		test("should handle instances with missing identifiers", async () => {
			const incompleteInstance: DBInstance = {
				PubliclyAccessible: true
			};

			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [incompleteInstance]
			});

			const result = await checkRdsPublicAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("RDS instance found without identifier or ARN");
		});
	});

	describe("Error Handling", () => {
		test("should return ERROR when API call fails", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).rejects(new Error("API Error"));

			const result = await checkRdsPublicAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking RDS instances: API Error");
		});

		test("should handle non-Error exceptions", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).rejects("String error");

			const result = await checkRdsPublicAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking RDS instances: String error");
		});
	});
});
