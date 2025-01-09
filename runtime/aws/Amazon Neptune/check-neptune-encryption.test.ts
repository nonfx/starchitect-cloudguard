// @ts-nocheck
import { NeptuneClient, DescribeDBClustersCommand } from "@aws-sdk/client-neptune";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkNeptuneEncryption from "./check-neptune-encryption";

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

describe("checkNeptuneEncryption", () => {
	beforeEach(() => {
		mockNeptuneClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when all clusters are encrypted", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockEncryptedCluster]
			});

			const result = await checkNeptuneEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("encrypted-cluster");
			expect(result.checks[0].resourceArn).toBe(mockEncryptedCluster.DBClusterArn);
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkNeptuneEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Neptune clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when clusters are not encrypted", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockUnencryptedCluster]
			});

			const result = await checkNeptuneEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Neptune cluster is not encrypted at rest");
		});

		it("should handle mixed encryption states", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockEncryptedCluster, mockUnencryptedCluster]
			});

			const result = await checkNeptuneEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle clusters without identifiers", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [{ StorageEncrypted: true }]
			});

			const result = await checkNeptuneEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without identifier or ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).rejects(new Error("API Error"));

			const result = await checkNeptuneEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe(
				"Error checking Neptune clusters: Failed to get Neptune clusters: API Error"
			);
		});

		it("should handle undefined DBClusters response", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({});

			const result = await checkNeptuneEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Neptune clusters found in the region");
		});
	});
});
