// @ts-nocheck
import { EC2Client, DescribeSnapshotsCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkEbsSnapshotPublicAccess from "./check-ebs-snapshot-public-access";

const mockEC2Client = mockClient(EC2Client);

const mockPublicSnapshot = {
	SnapshotId: "snap-public123",
	CreateVolumePermissions: [{ Group: "all" }]
};

const mockPrivateSnapshot = {
	SnapshotId: "snap-private456",
	CreateVolumePermissions: []
};

describe("checkEbsSnapshotPublicAccess", () => {
	beforeEach(() => {
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for private snapshots", async () => {
			mockEC2Client.on(DescribeSnapshotsCommand).resolves({
				Snapshots: [mockPrivateSnapshot]
			});

			const result = await checkEbsSnapshotPublicAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("snap-private456");
		});

		it("should return PASS for multiple private snapshots", async () => {
			mockEC2Client.on(DescribeSnapshotsCommand).resolves({
				Snapshots: [mockPrivateSnapshot, { ...mockPrivateSnapshot, SnapshotId: "snap-private789" }]
			});

			const result = await checkEbsSnapshotPublicAccess.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});

		it("should return NOTAPPLICABLE when no snapshots exist", async () => {
			mockEC2Client.on(DescribeSnapshotsCommand).resolves({
				Snapshots: []
			});

			const result = await checkEbsSnapshotPublicAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No EBS snapshots found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for public snapshots", async () => {
			mockEC2Client.on(DescribeSnapshotsCommand).resolves({
				Snapshots: [mockPublicSnapshot]
			});

			const result = await checkEbsSnapshotPublicAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("EBS snapshot has public access enabled");
		});

		it("should handle mixed public and private snapshots", async () => {
			mockEC2Client.on(DescribeSnapshotsCommand).resolves({
				Snapshots: [mockPublicSnapshot, mockPrivateSnapshot]
			});

			const result = await checkEbsSnapshotPublicAccess.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});

		it("should handle snapshots without IDs", async () => {
			mockEC2Client.on(DescribeSnapshotsCommand).resolves({
				Snapshots: [{ CreateVolumePermissions: [] }]
			});

			const result = await checkEbsSnapshotPublicAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Snapshot found without ID");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockEC2Client.on(DescribeSnapshotsCommand).rejects(new Error("API Error"));

			const result = await checkEbsSnapshotPublicAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking EBS snapshots: API Error");
		});

		it("should handle undefined Snapshots response", async () => {
			mockEC2Client.on(DescribeSnapshotsCommand).resolves({});

			const result = await checkEbsSnapshotPublicAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
