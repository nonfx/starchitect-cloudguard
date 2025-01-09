// @ts-nocheck
import { MemoryDBClient, DescribeClustersCommand } from "@aws-sdk/client-memorydb";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkMemoryDBEncryption from "./check-memorydb-encryption";

const mockMemoryDBClient = mockClient(MemoryDBClient);

const mockEncryptedCluster = {
	Name: "encrypted-cluster",
	ARN: "arn:aws:memorydb:us-east-1:123456789012:cluster/encrypted-cluster",
	TLSEnabled: true
};

const mockUnencryptedCluster = {
	Name: "unencrypted-cluster",
	ARN: "arn:aws:memorydb:us-east-1:123456789012:cluster/unencrypted-cluster",
	TLSEnabled: false
};

describe("checkMemoryDBEncryption", () => {
	beforeEach(() => {
		mockMemoryDBClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when cluster is encrypted", async () => {
			mockMemoryDBClient.on(DescribeClustersCommand).resolves({
				Clusters: [mockEncryptedCluster]
			});

			const result = await checkMemoryDBEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("encrypted-cluster");
			expect(result.checks[0].resourceArn).toBe(mockEncryptedCluster.ARN);
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockMemoryDBClient.on(DescribeClustersCommand).resolves({
				Clusters: []
			});

			const result = await checkMemoryDBEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No MemoryDB clusters found in the region");
		});

		it("should handle multiple compliant clusters", async () => {
			mockMemoryDBClient.on(DescribeClustersCommand).resolves({
				Clusters: [
					mockEncryptedCluster,
					{
						...mockEncryptedCluster,
						Name: "encrypted-cluster-2",
						ARN: "arn:aws:memorydb:us-east-1:123456789012:cluster/encrypted-cluster-2"
					}
				]
			});

			const result = await checkMemoryDBEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when cluster is not encrypted", async () => {
			mockMemoryDBClient.on(DescribeClustersCommand).resolves({
				Clusters: [mockUnencryptedCluster]
			});

			const result = await checkMemoryDBEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("MemoryDB cluster is not encrypted in transit");
		});

		it("should handle mixed compliance states", async () => {
			mockMemoryDBClient.on(DescribeClustersCommand).resolves({
				Clusters: [mockEncryptedCluster, mockUnencryptedCluster]
			});

			const result = await checkMemoryDBEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle clusters with missing properties", async () => {
			mockMemoryDBClient.on(DescribeClustersCommand).resolves({
				Clusters: [{ TLSEnabled: true }]
			});

			const result = await checkMemoryDBEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without name or ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockMemoryDBClient.on(DescribeClustersCommand).rejects(new Error("API Error"));

			const result = await checkMemoryDBEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking MemoryDB clusters: API Error");
		});

		it("should handle undefined Clusters response", async () => {
			mockMemoryDBClient.on(DescribeClustersCommand).resolves({});

			const result = await checkMemoryDBEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
