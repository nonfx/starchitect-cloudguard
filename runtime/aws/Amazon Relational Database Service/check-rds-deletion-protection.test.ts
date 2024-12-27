//@ts-nocheck
import {
	RDSClient,
	DescribeDBInstancesCommand,
	DescribeDBClustersCommand,
	type DBInstance,
	type DBCluster
} from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsDeletionProtection from "./check-rds-deletion-protection";

const mockRdsClient = mockClient(RDSClient);

const mockRdsInstance = (id: string, deletionProtection: boolean): DBInstance => ({
	DBInstanceIdentifier: id,
	DBInstanceArn: `arn:aws:rds:us-east-1:123456789012:db:${id}`,
	DeletionProtection: deletionProtection
});

const mockRdsCluster = (id: string, deletionProtection: boolean): DBCluster => ({
	DBClusterIdentifier: id,
	DBClusterArn: `arn:aws:rds:us-east-1:123456789012:cluster:${id}`,
	DeletionProtection: deletionProtection
});

describe("checkRdsDeletionProtection", () => {
	beforeEach(() => {
		mockRdsClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS when cluster deletion protection is enabled", async () => {
			mockRdsClient
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: [mockRdsCluster("cluster-1", true)]
				})
				.on(DescribeDBInstancesCommand)
				.resolves({
					DBInstances: []
				});

			const result = await checkRdsDeletionProtection.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("cluster-1");
		});

		test("should return PASS when standalone instance deletion protection is enabled", async () => {
			mockRdsClient
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: []
				})
				.on(DescribeDBInstancesCommand)
				.resolves({
					DBInstances: [mockRdsInstance("db-1", true)]
				});

			const result = await checkRdsDeletionProtection.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("db-1");
		});

		test("should handle multiple compliant resources", async () => {
			mockRdsClient
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: [mockRdsCluster("cluster-1", true)]
				})
				.on(DescribeDBInstancesCommand)
				.resolves({
					DBInstances: [mockRdsInstance("db-1", true)]
				});

			const result = await checkRdsDeletionProtection.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when cluster deletion protection is disabled", async () => {
			mockRdsClient
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: [mockRdsCluster("cluster-1", false)]
				})
				.on(DescribeDBInstancesCommand)
				.resolves({
					DBInstances: []
				});

			const result = await checkRdsDeletionProtection.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"Neither RDS cluster nor its instances have deletion protection enabled"
			);
		});

		test("should return FAIL when standalone instance deletion protection is disabled", async () => {
			mockRdsClient
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: []
				})
				.on(DescribeDBInstancesCommand)
				.resolves({
					DBInstances: [mockRdsInstance("db-1", false)]
				});

			const result = await checkRdsDeletionProtection.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"RDS instance does not have deletion protection enabled"
			);
		});

		test("should handle mixed compliance states", async () => {
			mockRdsClient
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: [mockRdsCluster("cluster-1", true), mockRdsCluster("cluster-2", false)]
				})
				.on(DescribeDBInstancesCommand)
				.resolves({
					DBInstances: [mockRdsInstance("db-1", true), mockRdsInstance("db-2", false)]
				});

			const result = await checkRdsDeletionProtection.execute("us-east-1");
			expect(result.checks).toHaveLength(4);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});

		test("should handle resources without identifiers", async () => {
			const incompleteCluster: DBCluster = {
				DeletionProtection: true
			};
			const incompleteInstance: DBInstance = {
				DeletionProtection: true
			};

			mockRdsClient
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: [incompleteCluster]
				})
				.on(DescribeDBInstancesCommand)
				.resolves({
					DBInstances: [incompleteInstance]
				});

			const result = await checkRdsDeletionProtection.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Cluster found without identifier or ARN");
		});
	});

	describe("Edge Cases and Error Handling", () => {
		test("should return NOTAPPLICABLE when no resources exist", async () => {
			mockRdsClient
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: []
				})
				.on(DescribeDBInstancesCommand)
				.resolves({
					DBInstances: []
				});

			const result = await checkRdsDeletionProtection.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS clusters or instances found in the region");
		});

		test("should handle pagination for instances", async () => {
			mockRdsClient
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: []
				})
				.on(DescribeDBInstancesCommand)
				.resolvesOnce({
					DBInstances: [mockRdsInstance("db-1", true)],
					Marker: "nextPage"
				})
				.resolvesOnce({
					DBInstances: [mockRdsInstance("db-2", false)]
				});

			const result = await checkRdsDeletionProtection.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});

		test("should return ERROR when API call fails", async () => {
			mockRdsClient
				.on(DescribeDBClustersCommand)
				.rejects(new Error("API Error"))
				.on(DescribeDBInstancesCommand)
				.resolves({
					DBInstances: []
				});

			const result = await checkRdsDeletionProtection.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS resources");
		});
	});
});
