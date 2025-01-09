// @ts-nocheck
import { BackupClient, ListBackupVaultsCommand, ListTagsCommand } from "@aws-sdk/client-backup";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkBackupVaultTags from "./check-backup-vault-tags";

const mockBackupClient = mockClient(BackupClient);

const mockVault1 = {
	BackupVaultName: "test-vault-1",
	BackupVaultArn: "arn:aws:backup:us-east-1:123456789012:backup-vault:test-vault-1"
};

const mockVault2 = {
	BackupVaultName: "test-vault-2",
	BackupVaultArn: "arn:aws:backup:us-east-1:123456789012:backup-vault:test-vault-2"
};

describe("checkBackupVaultTags", () => {
	beforeEach(() => {
		mockBackupClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when vault has user-defined tags", async () => {
			mockBackupClient.on(ListBackupVaultsCommand).resolves({ BackupVaultList: [mockVault1] });
			mockBackupClient.on(ListTagsCommand).resolves({ Tags: { "user-tag": "value" } });

			const result = await checkBackupVaultTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-vault-1");
		});

		it("should handle multiple vaults with tags correctly", async () => {
			mockBackupClient
				.on(ListBackupVaultsCommand)
				.resolves({ BackupVaultList: [mockVault1, mockVault2] });
			mockBackupClient.on(ListTagsCommand).resolves({ Tags: { "user-tag": "value" } });

			const result = await checkBackupVaultTags.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when vault has no user-defined tags", async () => {
			mockBackupClient.on(ListBackupVaultsCommand).resolves({ BackupVaultList: [mockVault1] });
			mockBackupClient.on(ListTagsCommand).resolves({ Tags: { "aws:created": "true" } });

			const result = await checkBackupVaultTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Backup vault does not have any user-defined tags");
		});

		it("should return FAIL when vault has empty tags", async () => {
			mockBackupClient.on(ListBackupVaultsCommand).resolves({ BackupVaultList: [mockVault1] });
			mockBackupClient.on(ListTagsCommand).resolves({ Tags: {} });

			const result = await checkBackupVaultTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no vaults exist", async () => {
			mockBackupClient.on(ListBackupVaultsCommand).resolves({ BackupVaultList: [] });

			const result = await checkBackupVaultTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No AWS Backup vaults found in the region");
		});

		it("should handle vault without name or ARN", async () => {
			mockBackupClient.on(ListBackupVaultsCommand).resolves({ BackupVaultList: [{}] });

			const result = await checkBackupVaultTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Backup vault found without name or ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListBackupVaults fails", async () => {
			mockBackupClient.on(ListBackupVaultsCommand).rejects(new Error("API Error"));

			const result = await checkBackupVaultTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking backup vaults");
		});

		it("should return ERROR when ListTags fails", async () => {
			mockBackupClient.on(ListBackupVaultsCommand).resolves({ BackupVaultList: [mockVault1] });
			mockBackupClient.on(ListTagsCommand).rejects(new Error("Tags API Error"));

			const result = await checkBackupVaultTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking vault tags");
		});
	});
});
