//@ts-nocheck
import { RDSClient, DescribeDBInstancesCommand, type DBInstance } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkRdsAccessControlAuthentication from "./check-rds-access-control-authentication";

const mockRdsClient = mockClient(RDSClient);

const mockCompliantInstance: DBInstance = {
	DBInstanceIdentifier: "compliant-db",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:compliant-db",
	PubliclyAccessible: false,
	IAMDatabaseAuthenticationEnabled: true
};

const mockNonCompliantInstance: DBInstance = {
	DBInstanceIdentifier: "non-compliant-db",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:non-compliant-db",
	PubliclyAccessible: true,
	IAMDatabaseAuthenticationEnabled: false
};

describe("checkRdsAccessControlAuthentication", () => {
	beforeEach(() => {
		mockRdsClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for RDS instances with proper access controls", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockCompliantInstance]
			});

			const result = await checkRdsAccessControlAuthentication.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("compliant-db");
			expect(result.checks[0]?.resourceArn).toBe(mockCompliantInstance.DBInstanceArn);
		});

		it("should return NOTAPPLICABLE when no RDS instances exist", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: []
			});

			const result = await checkRdsAccessControlAuthentication.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS instances found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for publicly accessible RDS instances", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockNonCompliantInstance]
			});

			const result = await checkRdsAccessControlAuthentication.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("publicly accessible");
			expect(result.checks[0]?.message).toContain("IAM authentication disabled");
		});

		it("should handle mixed compliance scenarios", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockCompliantInstance, mockNonCompliantInstance]
			});

			const result = await checkRdsAccessControlAuthentication.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle instances without identifiers", async () => {
			const incompleteInstance: DBInstance = {
				PubliclyAccessible: false
			};

			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [incompleteInstance]
			});

			const result = await checkRdsAccessControlAuthentication.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("RDS instance found without identifier");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).rejects(new Error("API Error"));

			const result = await checkRdsAccessControlAuthentication.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking RDS instances: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			mockRdsClient.on(DescribeDBInstancesCommand).rejects("String error");

			const result = await checkRdsAccessControlAuthentication.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking RDS instances: String error");
		});
	});
});
