//@ts-nocheck
import {
	RDSClient,
	DescribeDBSnapshotsCommand,
	DescribeDBClusterSnapshotsCommand,
	DescribeDBSnapshotAttributesCommand,
	DescribeDBClusterSnapshotAttributesCommand,
	type DBSnapshot,
	type DBClusterSnapshot,
	type DBSnapshotAttributesResult
} from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsSnapshotsPrivate from "./check-rds-snapshots-private";

const mockRDSClient = mockClient(RDSClient);

const mockDBSnapshot: DBSnapshot = {
	DBSnapshotIdentifier: "test-db-snapshot-1",
	DBSnapshotArn: "arn:aws:rds:us-east-1:123456789012:snapshot:test-db-snapshot-1"
};

const mockDBClusterSnapshot: DBClusterSnapshot = {
	DBClusterSnapshotIdentifier: "test-cluster-snapshot-1",
	DBClusterSnapshotArn: "arn:aws:rds:us-east-1:123456789012:snapshot:test-cluster-snapshot-1"
};

const mockPrivateSnapshotAttributes: DBSnapshotAttributesResult = {
	DBSnapshotAttributes: [
		{
			AttributeName: "restore",
			AttributeValues: []
		}
	]
};

const mockPublicSnapshotAttributes: DBSnapshotAttributesResult = {
	DBSnapshotAttributes: [
		{
			AttributeName: "restore",
			AttributeValues: ["all"]
		}
	]
};

describe("checkRdsSnapshotsPrivate", () => {
	beforeEach(() => {
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS for private DB snapshots", async () => {
			mockRDSClient.on(DescribeDBSnapshotsCommand).resolves({ DBSnapshots: [mockDBSnapshot] });
			mockRDSClient.on(DescribeDBClusterSnapshotsCommand).resolves({ DBClusterSnapshots: [] });
			mockRDSClient.on(DescribeDBSnapshotAttributesCommand).resolves({
				DBSnapshotAttributesResult: mockPrivateSnapshotAttributes
			});

			const result = await checkRdsSnapshotsPrivate.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-db-snapshot-1");
		});

		test("should return PASS for private cluster snapshots", async () => {
			mockRDSClient.on(DescribeDBSnapshotsCommand).resolves({ DBSnapshots: [] });
			mockRDSClient
				.on(DescribeDBClusterSnapshotsCommand)
				.resolves({ DBClusterSnapshots: [mockDBClusterSnapshot] });
			mockRDSClient.on(DescribeDBClusterSnapshotAttributesCommand).resolves({
				DBClusterSnapshotAttributesResult: {
					DBClusterSnapshotAttributes: [
						{
							AttributeName: "restore",
							AttributeValues: []
						}
					]
				}
			});

			const result = await checkRdsSnapshotsPrivate.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-cluster-snapshot-1");
		});

		test("should return NOTAPPLICABLE when no snapshots exist", async () => {
			mockRDSClient.on(DescribeDBSnapshotsCommand).resolves({ DBSnapshots: [] });
			mockRDSClient.on(DescribeDBClusterSnapshotsCommand).resolves({ DBClusterSnapshots: [] });

			const result = await checkRdsSnapshotsPrivate.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS snapshots found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL for public DB snapshots", async () => {
			mockRDSClient.on(DescribeDBSnapshotsCommand).resolves({ DBSnapshots: [mockDBSnapshot] });
			mockRDSClient.on(DescribeDBClusterSnapshotsCommand).resolves({ DBClusterSnapshots: [] });
			mockRDSClient.on(DescribeDBSnapshotAttributesCommand).resolves({
				DBSnapshotAttributesResult: mockPublicSnapshotAttributes
			});

			const result = await checkRdsSnapshotsPrivate.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe("RDS DB snapshot is publicly accessible");
		});

		test("should return FAIL for public cluster snapshots", async () => {
			mockRDSClient.on(DescribeDBSnapshotsCommand).resolves({ DBSnapshots: [] });
			mockRDSClient
				.on(DescribeDBClusterSnapshotsCommand)
				.resolves({ DBClusterSnapshots: [mockDBClusterSnapshot] });
			mockRDSClient.on(DescribeDBClusterSnapshotAttributesCommand).resolves({
				DBClusterSnapshotAttributesResult: {
					DBClusterSnapshotAttributes: [
						{
							AttributeName: "restore",
							AttributeValues: ["all"]
						}
					]
				}
			});

			const result = await checkRdsSnapshotsPrivate.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe("RDS cluster snapshot is publicly accessible");
		});

		test("should handle mixed public and private snapshots", async () => {
			mockRDSClient.on(DescribeDBSnapshotsCommand).resolves({
				DBSnapshots: [mockDBSnapshot, { ...mockDBSnapshot, DBSnapshotIdentifier: "test-2" }]
			});
			mockRDSClient.on(DescribeDBClusterSnapshotsCommand).resolves({
				DBClusterSnapshots: [mockDBClusterSnapshot]
			});
			mockRDSClient
				.on(DescribeDBSnapshotAttributesCommand)
				.resolvesOnce({
					DBSnapshotAttributesResult: mockPublicSnapshotAttributes
				})
				.resolvesOnce({
					DBSnapshotAttributesResult: mockPrivateSnapshotAttributes
				});
			mockRDSClient.on(DescribeDBClusterSnapshotAttributesCommand).resolves({
				DBClusterSnapshotAttributesResult: {
					DBClusterSnapshotAttributes: [
						{
							AttributeName: "restore",
							AttributeValues: []
						}
					]
				}
			});

			const result = await checkRdsSnapshotsPrivate.execute();
			expect(result.checks).toHaveLength(3);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[2]?.status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Error Handling", () => {
		test("should return ERROR when DB snapshots API call fails", async () => {
			mockRDSClient.on(DescribeDBSnapshotsCommand).rejects(new Error("API Error"));

			const result = await checkRdsSnapshotsPrivate.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS snapshots: API Error");
		});

		test("should return ERROR when snapshot attributes check fails", async () => {
			mockRDSClient.on(DescribeDBSnapshotsCommand).resolves({ DBSnapshots: [mockDBSnapshot] });
			mockRDSClient.on(DescribeDBClusterSnapshotsCommand).resolves({ DBClusterSnapshots: [] });
			mockRDSClient.on(DescribeDBSnapshotAttributesCommand).rejects(new Error("Attributes Error"));

			const result = await checkRdsSnapshotsPrivate.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking snapshot attributes");
		});
	});
});
