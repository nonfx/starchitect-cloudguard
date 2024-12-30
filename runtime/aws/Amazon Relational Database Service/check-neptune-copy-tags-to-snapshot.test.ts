// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { NeptuneClient, DescribeDBClustersCommand } from "@aws-sdk/client-neptune";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import neptuneCopyTagsToSnapshotCheck from "./check-neptune-copy-tags-to-snapshot.js";

const checkNeptuneCopyTagsToSnapshot = neptuneCopyTagsToSnapshotCheck.execute;

const mockNeptuneClient = mockClient(NeptuneClient);

const mockClusterWithTagCopying = {
	DBClusterIdentifier: "test-cluster-1",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster-1",
	CopyTagsToSnapshot: true
};

const mockClusterWithoutTagCopying = {
	DBClusterIdentifier: "test-cluster-2",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster-2",
	CopyTagsToSnapshot: false
};

describe("checkNeptuneCopyTagsToSnapshot", () => {
	beforeEach(() => {
		mockNeptuneClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when tag copying is enabled", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockClusterWithTagCopying]
			});

			const result = await checkNeptuneCopyTagsToSnapshot("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-cluster-1");
			expect(result.checks[0].resourceArn).toBe(mockClusterWithTagCopying.DBClusterArn);
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkNeptuneCopyTagsToSnapshot("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Neptune DB clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when tag copying is disabled", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockClusterWithoutTagCopying]
			});

			const result = await checkNeptuneCopyTagsToSnapshot("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Neptune DB cluster does not have tag copying to snapshots enabled"
			);
		});

		it("should handle mixed compliance states", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockClusterWithTagCopying, mockClusterWithoutTagCopying]
			});

			const result = await checkNeptuneCopyTagsToSnapshot("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle clusters without identifiers", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [{ CopyTagsToSnapshot: true }]
			});

			const result = await checkNeptuneCopyTagsToSnapshot("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without identifier or ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).rejects(new Error("API Error"));

			const result = await checkNeptuneCopyTagsToSnapshot("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking Neptune clusters: API Error");
		});

		it("should handle undefined DBClusters response", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({});

			const result = await checkNeptuneCopyTagsToSnapshot("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
