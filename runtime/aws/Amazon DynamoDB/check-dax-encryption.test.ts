//@ts-nocheck
import { DAXClient, DescribeClustersCommand } from "@aws-sdk/client-dax";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDaxEncryption from "./check-dax-encryption";

const mockDaxClient = mockClient(DAXClient);

const mockEncryptedCluster = {
	ClusterName: "encrypted-cluster",
	ClusterArn: "arn:aws:dax:us-east-1:123456789012:cluster/encrypted-cluster",
	SSEDescription: {
		Status: "ENABLED"
	}
};

const mockUnencryptedCluster = {
	ClusterName: "unencrypted-cluster",
	ClusterArn: "arn:aws:dax:us-east-1:123456789012:cluster/unencrypted-cluster",
	SSEDescription: {
		Status: "DISABLED"
	}
};

describe("checkDaxEncryption", () => {
	beforeEach(() => {
		mockDaxClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when DAX cluster is encrypted", async () => {
			mockDaxClient.on(DescribeClustersCommand).resolves({
				Clusters: [mockEncryptedCluster]
			});

			const result = await checkDaxEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("encrypted-cluster");
			expect(result.checks[0].resourceArn).toBe(mockEncryptedCluster.ClusterArn);
		});

		it("should return NOTAPPLICABLE when no DAX clusters exist", async () => {
			mockDaxClient.on(DescribeClustersCommand).resolves({
				Clusters: []
			});

			const result = await checkDaxEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No DAX clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when DAX cluster is not encrypted", async () => {
			mockDaxClient.on(DescribeClustersCommand).resolves({
				Clusters: [mockUnencryptedCluster]
			});

			const result = await checkDaxEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("DAX cluster is not encrypted at rest");
		});

		it("should handle multiple clusters with mixed encryption status", async () => {
			mockDaxClient.on(DescribeClustersCommand).resolves({
				Clusters: [mockEncryptedCluster, mockUnencryptedCluster]
			});

			const result = await checkDaxEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle clusters with missing name or ARN", async () => {
			mockDaxClient.on(DescribeClustersCommand).resolves({
				Clusters: [{ SSEDescription: { Status: "ENABLED" } }]
			});

			const result = await checkDaxEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without name or ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockDaxClient.on(DescribeClustersCommand).rejects(new Error("API Error"));

			const result = await checkDaxEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking DAX clusters: API Error");
		});

		it("should handle undefined Clusters response", async () => {
			mockDaxClient.on(DescribeClustersCommand).resolves({});

			const result = await checkDaxEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
