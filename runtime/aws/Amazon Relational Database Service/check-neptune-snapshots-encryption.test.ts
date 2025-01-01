// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { NeptuneClient, DescribeDBClusterSnapshotsCommand } from "@aws-sdk/client-neptune";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import neptuneSnapshotsEncryptionCheck from "./check-neptune-snapshots-encryption.js";

const checkNeptuneSnapshotsEncryption = neptuneSnapshotsEncryptionCheck.execute;

const mockNeptuneClient = mockClient(NeptuneClient);

const mockEncryptedSnapshot = {
	DBClusterSnapshotIdentifier: "encrypted-snapshot",
	DBClusterSnapshotArn: "arn:aws:rds:us-east-1:123456789012:cluster-snapshot:encrypted-snapshot",
	StorageEncrypted: true
};

const mockUnencryptedSnapshot = {
	DBClusterSnapshotIdentifier: "unencrypted-snapshot",
	DBClusterSnapshotArn: "arn:aws:rds:us-east-1:123456789012:cluster-snapshot:unencrypted-snapshot",
	StorageEncrypted: false
};

describe("checkNeptuneSnapshotsEncryption", () => {
	beforeEach(() => {
		mockNeptuneClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when all snapshots are encrypted", async () => {
			mockNeptuneClient.on(DescribeDBClusterSnapshotsCommand).resolves({
				DBClusterSnapshots: [mockEncryptedSnapshot]
			});

			const result = await checkNeptuneSnapshotsEncryption();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("encrypted-snapshot");
			expect(result.checks[0].resourceArn).toBe(mockEncryptedSnapshot.DBClusterSnapshotArn);
		});

		it("should return NOTAPPLICABLE when no snapshots exist", async () => {
			mockNeptuneClient.on(DescribeDBClusterSnapshotsCommand).resolves({
				DBClusterSnapshots: []
			});

			const result = await checkNeptuneSnapshotsEncryption();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Neptune DB cluster snapshots found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when snapshots are not encrypted", async () => {
			mockNeptuneClient.on(DescribeDBClusterSnapshotsCommand).resolves({
				DBClusterSnapshots: [mockUnencryptedSnapshot]
			});

			const result = await checkNeptuneSnapshotsEncryption();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Neptune DB cluster snapshot is not encrypted at rest");
		});

		it("should handle mixed encrypted and unencrypted snapshots", async () => {
			mockNeptuneClient.on(DescribeDBClusterSnapshotsCommand).resolves({
				DBClusterSnapshots: [mockEncryptedSnapshot, mockUnencryptedSnapshot]
			});

			const result = await checkNeptuneSnapshotsEncryption();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle snapshots with missing identifiers", async () => {
			mockNeptuneClient.on(DescribeDBClusterSnapshotsCommand).resolves({
				DBClusterSnapshots: [{ StorageEncrypted: true }]
			});

			const result = await checkNeptuneSnapshotsEncryption();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Snapshot found without identifier or ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockNeptuneClient.on(DescribeDBClusterSnapshotsCommand).rejects(new Error("API Error"));

			const result = await checkNeptuneSnapshotsEncryption();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking Neptune snapshots: API Error");
		});

		it("should handle undefined DBClusterSnapshots response", async () => {
			mockNeptuneClient.on(DescribeDBClusterSnapshotsCommand).resolves({});

			const result = await checkNeptuneSnapshotsEncryption();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
