// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { NeptuneClient, DescribeDBClustersCommand } from "@aws-sdk/client-neptune";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import neptuneClusterEncryptionCheck from "./check-neptune-cluster-encryption.js";

const checkNeptuneClusterEncryption = neptuneClusterEncryptionCheck.execute;

const mockNeptuneClient = mockClient(NeptuneClient);

const mockEncryptedCluster = {
	DBClusterIdentifier: "encrypted-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:encrypted-cluster",
	StorageEncrypted: true
};

const mockUnencryptedCluster = {
	DBClusterIdentifier: "unencrypted-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:unencrypted-cluster",
	StorageEncrypted: false
};

describe("checkNeptuneClusterEncryption", () => {
	beforeEach(() => {
		mockNeptuneClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Neptune cluster is encrypted", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockEncryptedCluster]
			});

			const result = await checkNeptuneClusterEncryption();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("encrypted-cluster");
			expect(result.checks[0].resourceArn).toBe(mockEncryptedCluster.DBClusterArn);
		});

		it("should return NOTAPPLICABLE when no Neptune clusters exist", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkNeptuneClusterEncryption();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Neptune DB clusters found in the region");
		});

		it("should handle multiple encrypted clusters", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [
					mockEncryptedCluster,
					{
						...mockEncryptedCluster,
						DBClusterIdentifier: "encrypted-cluster-2",
						DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:encrypted-cluster-2"
					}
				]
			});

			const result = await checkNeptuneClusterEncryption();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when Neptune cluster is not encrypted", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockUnencryptedCluster]
			});

			const result = await checkNeptuneClusterEncryption();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Neptune DB cluster is not encrypted at rest");
		});

		it("should handle mixed encrypted and unencrypted clusters", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockEncryptedCluster, mockUnencryptedCluster]
			});

			const result = await checkNeptuneClusterEncryption();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle clusters without identifiers", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [{ StorageEncrypted: true }]
			});

			const result = await checkNeptuneClusterEncryption();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without identifier or ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).rejects(new Error("API call failed"));

			const result = await checkNeptuneClusterEncryption();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking Neptune clusters: API call failed");
		});

		it("should handle undefined DBClusters response", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({});

			const result = await checkNeptuneClusterEncryption();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
