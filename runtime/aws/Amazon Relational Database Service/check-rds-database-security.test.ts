// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import {
	RDSClient,
	DescribeDBInstancesCommand,
	DescribeDBClustersCommand
} from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDatabaseSecurity from "./check-rds-database-security";

const mockRDSClient = mockClient(RDSClient);

const mockCompliantInstance = {
	DBInstanceIdentifier: "compliant-db-1",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:compliant-db-1",
	StorageEncrypted: true,
	PubliclyAccessible: false,
	BackupRetentionPeriod: 7,
	EnhancedMonitoringResourceArn: "arn:aws:monitoring"
};

const mockNonCompliantInstance = {
	DBInstanceIdentifier: "non-compliant-db-1",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:non-compliant-db-1",
	StorageEncrypted: false,
	PubliclyAccessible: true,
	BackupRetentionPeriod: 1,
	EnhancedMonitoringResourceArn: null
};

const mockCompliantCluster = {
	DBClusterIdentifier: "compliant-cluster-1",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:compliant-cluster-1",
	StorageEncrypted: true,
	BackupRetentionPeriod: 14,
	DeletionProtection: true
};

const mockNonCompliantCluster = {
	DBClusterIdentifier: "non-compliant-cluster-1",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:non-compliant-cluster-1",
	StorageEncrypted: false,
	BackupRetentionPeriod: 5,
	DeletionProtection: false
};

describe("checkDatabaseSecurity", () => {
	beforeEach(() => {
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for compliant DB instance", async () => {
			mockRDSClient
				.on(DescribeDBInstancesCommand)
				.resolves({ DBInstances: [mockCompliantInstance] });
			mockRDSClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [] });

			const result = await checkDatabaseSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("compliant-db-1");
		});

		it("should return PASS for compliant DB cluster", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] });
			mockRDSClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [mockCompliantCluster] });

			const result = await checkDatabaseSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("compliant-cluster-1");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for non-compliant DB instance", async () => {
			mockRDSClient
				.on(DescribeDBInstancesCommand)
				.resolves({ DBInstances: [mockNonCompliantInstance] });
			mockRDSClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [] });

			const result = await checkDatabaseSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("Storage is not encrypted");
			expect(result.checks[0].message).toContain("publicly accessible");
			expect(result.checks[0].message).toContain("Backup retention period");
			expect(result.checks[0].message).toContain("Enhanced monitoring");
		});

		it("should return FAIL for non-compliant DB cluster", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] });
			mockRDSClient
				.on(DescribeDBClustersCommand)
				.resolves({ DBClusters: [mockNonCompliantCluster] });

			const result = await checkDatabaseSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("Storage is not encrypted");
			expect(result.checks[0].message).toContain("Backup retention period");
			expect(result.checks[0].message).toContain("Deletion protection");
		});

		it("should handle mixed compliance results", async () => {
			mockRDSClient
				.on(DescribeDBInstancesCommand)
				.resolves({ DBInstances: [mockCompliantInstance, mockNonCompliantInstance] });
			mockRDSClient
				.on(DescribeDBClustersCommand)
				.resolves({ DBClusters: [mockCompliantCluster, mockNonCompliantCluster] });

			const result = await checkDatabaseSecurity.execute("us-east-1");
			expect(result.checks).toHaveLength(4);
			expect(result.checks.filter(check => check.status === ComplianceStatus.PASS)).toHaveLength(2);
			expect(result.checks.filter(check => check.status === ComplianceStatus.FAIL)).toHaveLength(2);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no databases exist", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] });
			mockRDSClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [] });

			const result = await checkDatabaseSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toContain("No RDS instances or clusters found");
		});

		it("should return ERROR when API calls fail", async () => {
			mockRDSClient.on(DescribeDBInstancesCommand).rejects(new Error("API Error"));

			const result = await checkDatabaseSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking database security configuration");
		});

		it("should skip instances with missing identifiers", async () => {
			const invalidInstance = { ...mockCompliantInstance, DBInstanceIdentifier: null };
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({ DBInstances: [invalidInstance] });
			mockRDSClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [] });

			const result = await checkDatabaseSecurity.execute("us-east-1");
			expect(result.checks).toHaveLength(0);
		});
	});
});
