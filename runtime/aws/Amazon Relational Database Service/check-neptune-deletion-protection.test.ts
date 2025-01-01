// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { NeptuneClient, DescribeDBClustersCommand } from "@aws-sdk/client-neptune";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import neptuneDeletionProtectionCheck from "./check-neptune-deletion-protection.js";

const checkNeptuneDeletionProtection = neptuneDeletionProtectionCheck.execute;

const mockNeptuneClient = mockClient(NeptuneClient);

const mockClusterWithProtection = {
	DBClusterIdentifier: "protected-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:protected-cluster",
	DeletionProtection: true
};

const mockClusterWithoutProtection = {
	DBClusterIdentifier: "unprotected-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:unprotected-cluster",
	DeletionProtection: false
};

describe("checkNeptuneDeletionProtection", () => {
	beforeEach(() => {
		mockNeptuneClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when deletion protection is enabled", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockClusterWithProtection]
			});

			const result = await checkNeptuneDeletionProtection("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("protected-cluster");
			expect(result.checks[0].resourceArn).toBe(mockClusterWithProtection.DBClusterArn);
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkNeptuneDeletionProtection("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Neptune DB clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when deletion protection is disabled", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockClusterWithoutProtection]
			});

			const result = await checkNeptuneDeletionProtection("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Neptune DB cluster does not have deletion protection enabled"
			);
		});

		it("should handle multiple clusters with mixed compliance", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockClusterWithProtection, mockClusterWithoutProtection]
			});

			const result = await checkNeptuneDeletionProtection("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle clusters with missing identifiers", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [{ DeletionProtection: true }]
			});

			const result = await checkNeptuneDeletionProtection("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without identifier or ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockNeptuneClient
				.on(DescribeDBClustersCommand)
				.rejects(new Error("Failed to describe DB clusters"));

			const result = await checkNeptuneDeletionProtection("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Neptune clusters");
		});

		it("should handle undefined DBClusters response", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({});

			const result = await checkNeptuneDeletionProtection("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
