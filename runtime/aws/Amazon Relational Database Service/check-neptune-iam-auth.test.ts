// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { NeptuneClient, DescribeDBClustersCommand } from "@aws-sdk/client-neptune";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import neptuneIamAuthCheck from "./check-neptune-iam-auth.js";

const checkNeptuneIamAuthCompliance = neptuneIamAuthCheck.execute;

const mockNeptuneClient = mockClient(NeptuneClient);

const mockCompliantCluster = {
	DBClusterIdentifier: "compliant-cluster",
	DBClusterArn: "arn:aws:neptune:us-east-1:123456789012:cluster:compliant-cluster",
	IAMDatabaseAuthenticationEnabled: true
};

const mockNonCompliantCluster = {
	DBClusterIdentifier: "non-compliant-cluster",
	DBClusterArn: "arn:aws:neptune:us-east-1:123456789012:cluster:non-compliant-cluster",
	IAMDatabaseAuthenticationEnabled: false
};

describe("checkNeptuneIamAuthCompliance", () => {
	beforeEach(() => {
		mockNeptuneClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when IAM authentication is enabled", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCompliantCluster]
			});

			const result = await checkNeptuneIamAuthCompliance("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("compliant-cluster");
			expect(result.checks[0].resourceArn).toBe(mockCompliantCluster.DBClusterArn);
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkNeptuneIamAuthCompliance("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Neptune DB clusters found in the region");
		});

		it("should handle multiple compliant clusters", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [
					mockCompliantCluster,
					{ ...mockCompliantCluster, DBClusterIdentifier: "compliant-cluster-2" }
				]
			});

			const result = await checkNeptuneIamAuthCompliance("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when IAM authentication is disabled", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockNonCompliantCluster]
			});

			const result = await checkNeptuneIamAuthCompliance("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"IAM database authentication is not enabled for the Neptune cluster"
			);
		});

		it("should handle mixed compliance status", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCompliantCluster, mockNonCompliantCluster]
			});

			const result = await checkNeptuneIamAuthCompliance("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle clusters without identifiers", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [{ IAMDatabaseAuthenticationEnabled: true }]
			});

			const result = await checkNeptuneIamAuthCompliance("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without identifier or ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockNeptuneClient
				.on(DescribeDBClustersCommand)
				.rejects(new Error("Failed to describe Neptune clusters"));

			const result = await checkNeptuneIamAuthCompliance("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Neptune clusters");
		});

		it("should handle undefined DBClusters response", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({});

			const result = await checkNeptuneIamAuthCompliance("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
