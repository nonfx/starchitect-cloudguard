// @ts-nocheck
import { DisksClient } from "@google-cloud/compute";
import { ComplianceStatus } from "../../types.js";
import checkDiskCSEKEncryption from "./gcp_disk_csek_encryption.js";

describe("checkDiskCSEKEncryption", () => {
	beforeEach(() => {
		// Reset the mock
		DisksClient.prototype.list = async () => [[]];
	});

	describe("Compliant Resources", () => {
		it("should return PASS when disk uses CSEK encryption", async () => {
			const mockDisk = {
				name: "test-disk-1",
				selfLink: "projects/test-project/zones/us-central1-a/disks/test-disk-1",
				diskEncryptionKey: {
					rawKey: "encrypted-key-data",
					sha256: "key-hash"
				}
			};

			DisksClient.prototype.list = async () => [[mockDisk]];

			const result = await checkDiskCSEKEncryption.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-disk-1");
		});

		it("should handle multiple disks with CSEK encryption", async () => {
			const mockDisks = [
				{
					name: "test-disk-1",
					selfLink: "projects/test-project/zones/us-central1-a/disks/test-disk-1",
					diskEncryptionKey: {
						rawKey: "encrypted-key-data-1"
					}
				},
				{
					name: "test-disk-2",
					selfLink: "projects/test-project/zones/us-central1-a/disks/test-disk-2",
					diskEncryptionKey: {
						rawKey: "encrypted-key-data-2"
					}
				}
			];

			DisksClient.prototype.list = async () => [mockDisks];

			const result = await checkDiskCSEKEncryption.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when disk does not use CSEK encryption", async () => {
			const mockDisk = {
				name: "test-disk-1",
				selfLink: "projects/test-project/zones/us-central1-a/disks/test-disk-1",
				diskEncryptionKey: {}
			};

			DisksClient.prototype.list = async () => [[mockDisk]];

			const result = await checkDiskCSEKEncryption.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain(
				"not encrypted with Customer-Supplied Encryption Keys"
			);
		});

		it("should return FAIL when disk has no encryption key", async () => {
			const mockDisk = {
				name: "test-disk-1",
				selfLink: "projects/test-project/zones/us-central1-a/disks/test-disk-1"
			};

			DisksClient.prototype.list = async () => [[mockDisk]];

			const result = await checkDiskCSEKEncryption.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no disks exist", async () => {
			DisksClient.prototype.list = async () => [[]];

			const result = await checkDiskCSEKEncryption.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No compute disks found in zone us-central1-a");
		});

		it("should handle disk without name", async () => {
			const mockDisk = {
				selfLink: "projects/test-project/zones/us-central1-a/disks/test-disk-1",
				diskEncryptionKey: {}
			};

			DisksClient.prototype.list = async () => [[mockDisk]];

			const result = await checkDiskCSEKEncryption.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.resourceName).toBe("Unknown Disk");
		});

		it("should handle missing project ID", async () => {
			const result = await checkDiskCSEKEncryption.execute("");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Project ID is not provided");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			DisksClient.prototype.list = async () => {
				throw new Error("API Error");
			};

			const result = await checkDiskCSEKEncryption.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking disk CSEK encryption: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			DisksClient.prototype.list = async () => {
				throw "Unknown error";
			};

			const result = await checkDiskCSEKEncryption.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking disk CSEK encryption: Unknown error");
		});
	});
});
