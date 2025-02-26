// @ts-nocheck
import {
	BackupClient,
	ListBackupVaultsCommand,
	ListRecoveryPointsByBackupVaultCommand,
	DescribeRecoveryPointCommand
} from "@aws-sdk/client-backup";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkBackupRecoveryPointEncryption from "./check-backup-recovery-point-encryption";

const mockBackupClient = mockClient(BackupClient);

const mockVault = {
	BackupVaultName: "test-vault",
	BackupVaultArn: "arn:aws:backup:us-east-1:123456789012:backup-vault:test-vault"
};

const mockRecoveryPoint = {
	RecoveryPointArn: "arn:aws:backup:us-east-1:123456789012:recovery-point:test-point",
	BackupVaultName: "test-vault"
};

describe("checkBackupRecoveryPointEncryption", () => {
	beforeEach(() => {
		mockBackupClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when recovery points are encrypted", async () => {
			mockBackupClient
				.on(ListBackupVaultsCommand)
				.resolves({ BackupVaultList: [mockVault] })
				.on(ListRecoveryPointsByBackupVaultCommand)
				.resolves({ RecoveryPoints: [mockRecoveryPoint] })
				.on(DescribeRecoveryPointCommand)
				.resolves({
					EncryptionKeyArn: "arn:aws:kms:us-east-1:123456789012:key/test-key"
				});

			const result = await checkBackupRecoveryPointEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceArn).toBe(mockRecoveryPoint.RecoveryPointArn);
		});

		it("should return NOTAPPLICABLE when no vaults exist", async () => {
			mockBackupClient.on(ListBackupVaultsCommand).resolves({ BackupVaultList: [] });

			const result = await checkBackupRecoveryPointEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No backup vaults found in the region");
		});

		it("should return NOTAPPLICABLE when vault has no recovery points", async () => {
			mockBackupClient
				.on(ListBackupVaultsCommand)
				.resolves({ BackupVaultList: [mockVault] })
				.on(ListRecoveryPointsByBackupVaultCommand)
				.resolves({ RecoveryPoints: [] });

			const result = await checkBackupRecoveryPointEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No recovery points found in vault");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when recovery points are not encrypted", async () => {
			mockBackupClient
				.on(ListBackupVaultsCommand)
				.resolves({ BackupVaultList: [mockVault] })
				.on(ListRecoveryPointsByBackupVaultCommand)
				.resolves({ RecoveryPoints: [mockRecoveryPoint] })
				.on(DescribeRecoveryPointCommand)
				.resolves({ EncryptionKeyArn: undefined });

			const result = await checkBackupRecoveryPointEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Recovery point is not encrypted at rest");
		});

		it("should handle mixed encrypted and unencrypted recovery points", async () => {
			const mockPoints = [
				{ ...mockRecoveryPoint, RecoveryPointArn: "arn:1" },
				{ ...mockRecoveryPoint, RecoveryPointArn: "arn:2" }
			];

			mockBackupClient
				.on(ListBackupVaultsCommand)
				.resolves({ BackupVaultList: [mockVault] })
				.on(ListRecoveryPointsByBackupVaultCommand)
				.resolves({ RecoveryPoints: mockPoints })
				.on(DescribeRecoveryPointCommand)
				.resolvesOnce({ EncryptionKeyArn: "key-1" })
				.resolvesOnce({ EncryptionKeyArn: undefined });

			const result = await checkBackupRecoveryPointEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListBackupVaults fails", async () => {
			mockBackupClient.on(ListBackupVaultsCommand).rejects(new Error("API Error"));

			const result = await checkBackupRecoveryPointEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking backup vaults");
		});

		it("should handle errors for specific recovery points", async () => {
			mockBackupClient
				.on(ListBackupVaultsCommand)
				.resolves({ BackupVaultList: [mockVault] })
				.on(ListRecoveryPointsByBackupVaultCommand)
				.resolves({ RecoveryPoints: [mockRecoveryPoint] })
				.on(DescribeRecoveryPointCommand)
				.rejects(new Error("Access Denied"));

			const result = await checkBackupRecoveryPointEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking recovery point");
		});

		it("should handle missing vault names", async () => {
			mockBackupClient
				.on(ListBackupVaultsCommand)
				.resolves({ BackupVaultList: [{ BackupVaultArn: "arn:test" }] });

			const result = await checkBackupRecoveryPointEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Backup vault found without name");
		});
	});
});
