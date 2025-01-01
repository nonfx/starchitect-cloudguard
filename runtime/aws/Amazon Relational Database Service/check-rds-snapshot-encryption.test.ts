//@ts-nocheck
import {
	RDSClient,
	DescribeDBSnapshotsCommand,
	DescribeDBClusterSnapshotsCommand,
	type DBSnapshot,
	type DBClusterSnapshot
} from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";

import checkRdsSnapshotEncryption from "./check-rds-snapshot-encryption";

const mockRDSClient = mockClient(RDSClient);

const mockDBSnapshot: DBSnapshot = {
	DBSnapshotIdentifier: "test-db-snapshot-1",
	DBSnapshotArn: "arn:aws:rds:us-east-1:123456789012:snapshot:test-db-snapshot-1",
	Encrypted: true
};

const mockDBClusterSnapshot: DBClusterSnapshot = {
	DBClusterSnapshotIdentifier: "test-cluster-snapshot-1",
	DBClusterSnapshotArn:
		"arn:aws:rds:us-east-1:123456789012:cluster-snapshot:test-cluster-snapshot-1",
	StorageEncrypted: true
};

describe("checkRdsSnapshotEncryption", () => {
	beforeEach(() => {
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS for encrypted DB snapshots", async () => {
			mockRDSClient.on(DescribeDBSnapshotsCommand).resolves({ DBSnapshots: [mockDBSnapshot] });
			mockRDSClient.on(DescribeDBClusterSnapshotsCommand).resolves({ DBClusterSnapshots: [] });

			const result = await checkRdsSnapshotEncryption.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe(mockDBSnapshot.DBSnapshotIdentifier);
		});

		test("should return PASS for encrypted cluster snapshots", async () => {
			mockRDSClient.on(DescribeDBSnapshotsCommand).resolves({ DBSnapshots: [] });
			mockRDSClient
				.on(DescribeDBClusterSnapshotsCommand)
				.resolves({ DBClusterSnapshots: [mockDBClusterSnapshot] });

			const result = await checkRdsSnapshotEncryption.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe(
				mockDBClusterSnapshot.DBClusterSnapshotIdentifier
			);
		});

		test("should return NOTAPPLICABLE when no snapshots exist", async () => {
			mockRDSClient.on(DescribeDBSnapshotsCommand).resolves({ DBSnapshots: [] });
			mockRDSClient.on(DescribeDBClusterSnapshotsCommand).resolves({ DBClusterSnapshots: [] });

			const result = await checkRdsSnapshotEncryption.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS snapshots found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL for unencrypted DB snapshots", async () => {
			const unencryptedSnapshot: DBSnapshot = { ...mockDBSnapshot, Encrypted: false };
			mockRDSClient.on(DescribeDBSnapshotsCommand).resolves({ DBSnapshots: [unencryptedSnapshot] });
			mockRDSClient.on(DescribeDBClusterSnapshotsCommand).resolves({ DBClusterSnapshots: [] });

			const result = await checkRdsSnapshotEncryption.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe("DB snapshot is not encrypted at rest");
		});

		test("should return FAIL for unencrypted cluster snapshots", async () => {
			const unencryptedClusterSnapshot: DBClusterSnapshot = {
				...mockDBClusterSnapshot,
				StorageEncrypted: false
			};
			mockRDSClient.on(DescribeDBSnapshotsCommand).resolves({ DBSnapshots: [] });
			mockRDSClient
				.on(DescribeDBClusterSnapshotsCommand)
				.resolves({ DBClusterSnapshots: [unencryptedClusterSnapshot] });

			const result = await checkRdsSnapshotEncryption.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe("DB cluster snapshot is not encrypted at rest");
		});

		test("should handle mixed encryption states", async () => {
			mockRDSClient.on(DescribeDBSnapshotsCommand).resolves({
				DBSnapshots: [
					mockDBSnapshot,
					{ ...mockDBSnapshot, DBSnapshotIdentifier: "test-2", Encrypted: false }
				]
			});
			mockRDSClient.on(DescribeDBClusterSnapshotsCommand).resolves({ DBClusterSnapshots: [] });

			const result = await checkRdsSnapshotEncryption.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		test("should return ERROR when API calls fail", async () => {
			mockRDSClient.on(DescribeDBSnapshotsCommand).rejects(new Error("API Error"));

			const result = await checkRdsSnapshotEncryption.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS snapshots");
		});

		test("should handle missing identifiers", async () => {
			const invalidSnapshot: DBSnapshot = {
				DBSnapshotIdentifier: undefined,
				DBSnapshotArn: undefined
			};
			mockRDSClient.on(DescribeDBSnapshotsCommand).resolves({ DBSnapshots: [invalidSnapshot] });
			mockRDSClient.on(DescribeDBClusterSnapshotsCommand).resolves({ DBClusterSnapshots: [] });

			const result = await checkRdsSnapshotEncryption.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("DB Snapshot missing identifier or ARN");
		});
	});
});
