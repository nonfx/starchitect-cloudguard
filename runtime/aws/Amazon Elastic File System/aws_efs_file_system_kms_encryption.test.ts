import { EFSClient, DescribeFileSystemsCommand } from "@aws-sdk/client-efs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkEfsEncryption from "./aws_efs_file_system_kms_encryption";

const mockEfsClient = mockClient(EFSClient);

const mockEncryptedFileSystem = {
	FileSystemId: "fs-12345678",
	FileSystemArn: "arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-12345678",
	Encrypted: true,
	KmsKeyId: "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
};

const mockUnencryptedFileSystem = {
	FileSystemId: "fs-87654321",
	FileSystemArn: "arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-87654321",
	Encrypted: false
};

describe("checkEfsEncryption", () => {
	beforeEach(() => {
		mockEfsClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when EFS is encrypted with KMS", async () => {
			mockEfsClient.on(DescribeFileSystemsCommand).resolves({
				FileSystems: [mockEncryptedFileSystem]
			});

			const result = await checkEfsEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe(mockEncryptedFileSystem.FileSystemId);
			expect(result.checks[0].resourceArn).toBe(mockEncryptedFileSystem.FileSystemArn);
		});

		it("should return NOTAPPLICABLE when no EFS file systems exist", async () => {
			mockEfsClient.on(DescribeFileSystemsCommand).resolves({
				FileSystems: []
			});

			const result = await checkEfsEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No EFS file systems found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when EFS is not encrypted", async () => {
			mockEfsClient.on(DescribeFileSystemsCommand).resolves({
				FileSystems: [mockUnencryptedFileSystem]
			});

			const result = await checkEfsEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("EFS file system is not encrypted with KMS");
		});

		it("should handle multiple file systems with mixed encryption status", async () => {
			mockEfsClient.on(DescribeFileSystemsCommand).resolves({
				FileSystems: [mockEncryptedFileSystem, mockUnencryptedFileSystem]
			});

			const result = await checkEfsEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle file systems without FileSystemId", async () => {
			mockEfsClient.on(DescribeFileSystemsCommand).resolves({
				FileSystems: [{ Encrypted: true }]
			});

			const result = await checkEfsEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("File system found without ID");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockEfsClient.on(DescribeFileSystemsCommand).rejects(new Error("API Error"));

			const result = await checkEfsEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking EFS file systems: API Error");
		});

		it("should handle undefined FileSystems response", async () => {
			mockEfsClient.on(DescribeFileSystemsCommand).resolves({});

			const result = await checkEfsEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
