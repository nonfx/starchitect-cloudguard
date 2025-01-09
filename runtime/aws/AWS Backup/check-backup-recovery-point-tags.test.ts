// @ts-nocheck
import {
	BackupClient,
	ListRecoveryPointsByBackupVaultCommand,
	ListBackupVaultsCommand
} from "@aws-sdk/client-backup";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkBackupRecoveryPointTags from "./check-backup-recovery-point-tags";

const mockBackupClient = mockClient(BackupClient);

const mockVault = {
	BackupVaultName: "test-vault",
	BackupVaultArn: "arn:aws:backup:us-east-1:123456789012:backup-vault:test-vault"
};

const mockRecoveryPoint = {
	RecoveryPointArn: "arn:aws:backup:us-east-1:123456789012:recovery-point:1234567890"
};

describe("checkBackupRecoveryPointTags", () => {
	beforeEach(() => {
		mockBackupClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when recovery points have user-defined tags", async () => {
			mockBackupClient.on(ListBackupVaultsCommand).resolves({ BackupVaultList: [mockVault] });
			mockBackupClient.on(ListRecoveryPointsByBackupVaultCommand).resolves({
				RecoveryPoints: [
					{
						...mockRecoveryPoint,
						Tags: { "user-tag": "value" }
					}
				]
			});

			const result = await checkBackupRecoveryPointTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceArn).toBe(mockRecoveryPoint.RecoveryPointArn);
		});

		it("should return PASS when recovery points have both user and system tags", async () => {
			mockBackupClient.on(ListBackupVaultsCommand).resolves({ BackupVaultList: [mockVault] });
			mockBackupClient.on(ListRecoveryPointsByBackupVaultCommand).resolves({
				RecoveryPoints: [
					{
						...mockRecoveryPoint,
						Tags: {
							"user-tag": "value",
							"aws:backup:source-resource": "resource-id"
						}
					}
				]
			});

			const result = await checkBackupRecoveryPointTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when recovery points have no tags", async () => {
			mockBackupClient.on(ListBackupVaultsCommand).resolves({ BackupVaultList: [mockVault] });
			mockBackupClient.on(ListRecoveryPointsByBackupVaultCommand).resolves({
				RecoveryPoints: [
					{
						...mockRecoveryPoint,
						Tags: {}
					}
				]
			});

			const result = await checkBackupRecoveryPointTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Recovery point has no user-defined tags");
		});

		it("should return FAIL when recovery points only have system tags", async () => {
			mockBackupClient.on(ListBackupVaultsCommand).resolves({ BackupVaultList: [mockVault] });
			mockBackupClient.on(ListRecoveryPointsByBackupVaultCommand).resolves({
				RecoveryPoints: [
					{
						...mockRecoveryPoint,
						Tags: { "aws:backup:source-resource": "resource-id" }
					}
				]
			});

			const result = await checkBackupRecoveryPointTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Special Cases", () => {
		it("should return NOTAPPLICABLE when no backup vaults exist", async () => {
			mockBackupClient.on(ListBackupVaultsCommand).resolves({ BackupVaultList: [] });

			const result = await checkBackupRecoveryPointTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No AWS Backup vaults found in the region");
		});

		it("should return NOTAPPLICABLE when vault has no recovery points", async () => {
			mockBackupClient.on(ListBackupVaultsCommand).resolves({ BackupVaultList: [mockVault] });
			mockBackupClient.on(ListRecoveryPointsByBackupVaultCommand).resolves({ RecoveryPoints: [] });

			const result = await checkBackupRecoveryPointTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No recovery points found in vault");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListBackupVaults fails", async () => {
			mockBackupClient.on(ListBackupVaultsCommand).rejects(new Error("API Error"));

			const result = await checkBackupRecoveryPointTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking backup vaults");
		});

		it("should return ERROR when ListRecoveryPointsByBackupVault fails", async () => {
			mockBackupClient.on(ListBackupVaultsCommand).resolves({ BackupVaultList: [mockVault] });
			mockBackupClient
				.on(ListRecoveryPointsByBackupVaultCommand)
				.rejects(new Error("Access Denied"));

			const result = await checkBackupRecoveryPointTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking recovery points");
		});
	});
});
