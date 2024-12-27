import {
	RDSClient,
	DescribeDBClustersCommand,
	DescribeDBClusterParameterGroupsCommand,
	DescribeDBClusterParametersCommand,
	type DBCluster
} from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkAuroraEncryptionInTransit from "./check-aurora-encryption-in-transit";

const mockRDSClient = mockClient(RDSClient);

const mockPostgresCluster: DBCluster = {
	DBClusterIdentifier: "postgres-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:postgres-cluster",
	DBClusterParameterGroup: "postgres-param-group"
};

const mockMySQLCluster: DBCluster = {
	DBClusterIdentifier: "mysql-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:mysql-cluster",
	DBClusterParameterGroup: "mysql-param-group"
};

describe("checkAuroraEncryptionInTransit", () => {
	beforeEach(() => {
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for PostgreSQL cluster with SSL enforced", async () => {
			mockRDSClient
				.on(DescribeDBClustersCommand)
				.resolves({ DBClusters: [mockPostgresCluster] })
				.on(DescribeDBClusterParameterGroupsCommand)
				.resolves({
					DBClusterParameterGroups: [
						{
							DBParameterGroupFamily: "aurora-postgresql13"
						}
					]
				})
				.on(DescribeDBClusterParametersCommand)
				.resolves({
					Parameters: [{ ParameterName: "rds.force_ssl", ParameterValue: "1" }]
				});

			const result = await checkAuroraEncryptionInTransit.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("postgres-cluster");
		});

		it("should return PASS for MySQL cluster with SSL enforced", async () => {
			mockRDSClient
				.on(DescribeDBClustersCommand)
				.resolves({ DBClusters: [mockMySQLCluster] })
				.on(DescribeDBClusterParameterGroupsCommand)
				.resolves({
					DBClusterParameterGroups: [
						{
							DBParameterGroupFamily: "aurora-mysql5.7"
						}
					]
				})
				.on(DescribeDBClusterParametersCommand)
				.resolves({
					Parameters: [{ ParameterName: "require_secure_transport", ParameterValue: "1" }]
				});

			const result = await checkAuroraEncryptionInTransit.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("mysql-cluster");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for PostgreSQL cluster without SSL enforcement", async () => {
			mockRDSClient
				.on(DescribeDBClustersCommand)
				.resolves({ DBClusters: [mockPostgresCluster] })
				.on(DescribeDBClusterParameterGroupsCommand)
				.resolves({
					DBClusterParameterGroups: [
						{
							DBParameterGroupFamily: "aurora-postgresql13"
						}
					]
				})
				.on(DescribeDBClusterParametersCommand)
				.resolves({
					Parameters: [{ ParameterName: "rds.force_ssl", ParameterValue: "0" }]
				});

			const result = await checkAuroraEncryptionInTransit.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"SSL connections are not enforced for this Aurora cluster"
			);
		});

		it("should return FAIL for MySQL cluster without SSL enforcement", async () => {
			mockRDSClient
				.on(DescribeDBClustersCommand)
				.resolves({ DBClusters: [mockMySQLCluster] })
				.on(DescribeDBClusterParameterGroupsCommand)
				.resolves({
					DBClusterParameterGroups: [
						{
							DBParameterGroupFamily: "aurora-mysql5.7"
						}
					]
				})
				.on(DescribeDBClusterParametersCommand)
				.resolves({
					Parameters: [{ ParameterName: "require_secure_transport", ParameterValue: "0" }]
				});

			const result = await checkAuroraEncryptionInTransit.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [] });

			const result = await checkAuroraEncryptionInTransit.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Aurora clusters found in the region");
		});

		it("should return ERROR when API call fails", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).rejects(new Error("API Error"));

			const result = await checkAuroraEncryptionInTransit.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Aurora clusters");
		});

		it("should handle missing parameter group information", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [
					{
						DBClusterIdentifier: "invalid-cluster"
					} as DBCluster
				]
			});

			const result = await checkAuroraEncryptionInTransit.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without identifier or parameter group");
		});
	});
});
