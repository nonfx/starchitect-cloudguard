//@ts-nocheck
import { RDSClient, DescribeDBClustersCommand, type DBCluster } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types";
import checkAuroraEncryption from "./check-aurora-encryption";

const mockRDSClient = mockClient(RDSClient);

const mockEncryptedCluster: DBCluster = {
	DBClusterIdentifier: "encrypted-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:encrypted-cluster",
	StorageEncrypted: true,
	KmsKeyId: "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
};

const mockUnencryptedCluster: DBCluster = {
	DBClusterIdentifier: "unencrypted-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:unencrypted-cluster",
	StorageEncrypted: false
};

const mockEncryptedNoKMSCluster: DBCluster = {
	DBClusterIdentifier: "encrypted-no-kms-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:encrypted-no-kms-cluster",
	StorageEncrypted: true,
	KmsKeyId: ""
};

describe("checkAuroraEncryption", () => {
	beforeEach(() => {
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for properly encrypted clusters with KMS keys", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockEncryptedCluster]
			});

			const result = await checkAuroraEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("encrypted-cluster");
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkAuroraEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Aurora clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for unencrypted clusters", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockUnencryptedCluster]
			});

			const result = await checkAuroraEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Aurora cluster does not have encryption at rest enabled"
			);
		});

		it("should return FAIL for encrypted clusters without KMS keys", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockEncryptedNoKMSCluster]
			});

			const result = await checkAuroraEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Aurora cluster is encrypted but does not have a KMS key specified"
			);
		});

		it("should handle mixed compliance scenarios", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockEncryptedCluster, mockUnencryptedCluster, mockEncryptedNoKMSCluster]
			});

			const result = await checkAuroraEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(3);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[2].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).rejects(new Error("API Error"));

			const result = await checkAuroraEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking Aurora clusters: API Error");
		});

		it("should handle clusters with missing identifiers", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [{ StorageEncrypted: true } as DBCluster]
			});

			const result = await checkAuroraEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without identifier or ARN");
		});
	});
});
