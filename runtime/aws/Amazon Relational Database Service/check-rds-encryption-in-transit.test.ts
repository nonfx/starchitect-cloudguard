import {
	RDSClient,
	DescribeDBClustersCommand,
	DescribeDBClusterParametersCommand,
	type DBCluster
} from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsEncryptionInTransit from "./check-rds-encryption-in-transit";

const mockRdsClient = mockClient(RDSClient);

const mockMySQLCluster = (id: string, requireSSL: boolean): DBCluster => ({
	DBClusterIdentifier: id,
	DBClusterArn: `arn:aws:rds:us-east-1:123456789012:cluster:${id}`,
	DBClusterParameterGroup: `${id}-params`,
	Engine: "aurora-mysql"
});

const mockPostgresCluster = (id: string, requireSSL: boolean): DBCluster => ({
	DBClusterIdentifier: id,
	DBClusterArn: `arn:aws:rds:us-east-1:123456789012:cluster:${id}`,
	DBClusterParameterGroup: `${id}-params`,
	Engine: "aurora-postgresql"
});

describe("checkRdsEncryptionInTransit", () => {
	beforeEach(() => {
		mockRdsClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS when MySQL cluster requires SSL", async () => {
			const cluster = mockMySQLCluster("mysql-ssl", true);
			mockRdsClient
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: [cluster]
				})
				.on(DescribeDBClusterParametersCommand)
				.resolves({
					Parameters: [
						{
							ParameterName: "require_secure_transport",
							ParameterValue: "1"
						}
					]
				});

			const result = await checkRdsEncryptionInTransit.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("mysql-ssl");
		});

		test("should return PASS when PostgreSQL cluster requires SSL", async () => {
			const cluster = mockPostgresCluster("postgres-ssl", true);
			mockRdsClient
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: [cluster]
				})
				.on(DescribeDBClusterParametersCommand)
				.resolves({
					Parameters: [
						{
							ParameterName: "rds.force_ssl",
							ParameterValue: "on"
						}
					]
				});

			const result = await checkRdsEncryptionInTransit.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("postgres-ssl");
		});

		test("should return NOTAPPLICABLE when no RDS clusters exist", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkRdsEncryptionInTransit.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when MySQL cluster does not require SSL", async () => {
			const cluster = mockMySQLCluster("mysql-nossl", false);
			mockRdsClient
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: [cluster]
				})
				.on(DescribeDBClusterParametersCommand)
				.resolves({
					Parameters: [
						{
							ParameterName: "require_secure_transport",
							ParameterValue: "0"
						}
					]
				});

			const result = await checkRdsEncryptionInTransit.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("does not require SSL/TLS connections");
		});

		test("should return FAIL when PostgreSQL cluster does not require SSL", async () => {
			const cluster = mockPostgresCluster("postgres-nossl", false);
			mockRdsClient
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: [cluster]
				})
				.on(DescribeDBClusterParametersCommand)
				.resolves({
					Parameters: [
						{
							ParameterName: "rds.force_ssl",
							ParameterValue: "off"
						}
					]
				});

			const result = await checkRdsEncryptionInTransit.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("does not require SSL/TLS connections");
		});

		test("should handle clusters without parameter groups", async () => {
			const incompleteCluster: DBCluster = {
				DBClusterIdentifier: "no-params",
				DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:no-params",
				Engine: "aurora-mysql"
			};

			mockRdsClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [incompleteCluster]
			});

			const result = await checkRdsEncryptionInTransit.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("No parameter group found for cluster");
		});

		test("should handle mixed compliance states", async () => {
			const mysqlCluster = mockMySQLCluster("mysql-ssl", true);
			const postgresCluster = mockPostgresCluster("postgres-nossl", false);

			mockRdsClient
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: [mysqlCluster, postgresCluster]
				})
				.on(DescribeDBClusterParametersCommand)
				.resolves({
					Parameters: [
						{
							ParameterName: "require_secure_transport",
							ParameterValue: "1"
						},
						{
							ParameterName: "rds.force_ssl",
							ParameterValue: "off"
						}
					]
				});

			const result = await checkRdsEncryptionInTransit.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		test("should return ERROR when cluster API call fails", async () => {
			mockRdsClient.on(DescribeDBClustersCommand).rejects(new Error("API Error"));

			const result = await checkRdsEncryptionInTransit.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS clusters");
		});

		test("should return ERROR when parameter API call fails", async () => {
			const cluster = mockMySQLCluster("mysql-error", true);
			mockRdsClient
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: [cluster]
				})
				.on(DescribeDBClusterParametersCommand)
				.rejects(new Error("Parameter API Error"));

			const result = await checkRdsEncryptionInTransit.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking parameter group");
		});

		test("should handle pagination for parameters", async () => {
			const cluster = mockMySQLCluster("mysql-paginated", true);
			mockRdsClient
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: [cluster]
				})
				.on(DescribeDBClusterParametersCommand)
				.resolvesOnce({
					Parameters: [{ ParameterName: "other_param", ParameterValue: "value" }],
					Marker: "nextPage"
				})
				.resolvesOnce({
					Parameters: [{ ParameterName: "require_secure_transport", ParameterValue: "1" }]
				});

			const result = await checkRdsEncryptionInTransit.execute("us-east-1");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});
	});
});
