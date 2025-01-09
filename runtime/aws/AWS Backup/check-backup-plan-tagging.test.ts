// @ts-nocheck
import { BackupClient, ListBackupPlansCommand, ListTagsCommand } from "@aws-sdk/client-backup";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkBackupPlanTagging from "./check-backup-plan-tagging";

const mockBackupClient = mockClient(BackupClient);

const mockBackupPlanWithTags = {
	BackupPlanName: "backup-plan-1",
	BackupPlanArn: "arn:aws:backup:us-east-1:123456789012:backup-plan:backup-plan-1",
	BackupPlanTags: {
		Environment: "Production",
		Owner: "TeamA"
	}
};

const mockBackupPlanWithoutTags = {
	BackupPlanName: "backup-plan-2",
	BackupPlanArn: "arn:aws:backup:us-east-1:123456789012:backup-plan:backup-plan-2",
	BackupPlanTags: {}
};

const mockBackupPlanWithSystemTags = {
	BackupPlanName: "backup-plan-3",
	BackupPlanArn: "arn:aws:backup:us-east-1:123456789012:backup-plan:backup-plan-3",
	BackupPlanTags: {
		"aws:createdBy": "AWS-Service",
		"aws:backup:plan-id": "12345"
	}
};

describe("checkBackupPlanTagging", () => {
	beforeEach(() => {
		mockBackupClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when backup plan has user-defined tags", async () => {
			mockBackupClient
				.on(ListBackupPlansCommand)
				.resolves({
					BackupPlansList: [mockBackupPlanWithTags]
				})
				.on(ListTagsCommand)
				.resolves({
					Tags: {
						Environment: "Production",
						Owner: "TeamA"
					}
				});

			const result = await checkBackupPlanTagging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("backup-plan-1");
			expect(result.checks[0].resourceArn).toBe(mockBackupPlanWithTags.BackupPlanArn);
		});

		it("should handle multiple backup plans with mixed tag status", async () => {
			mockBackupClient
				.on(ListBackupPlansCommand)
				.resolves({
					BackupPlansList: [mockBackupPlanWithTags, mockBackupPlanWithoutTags]
				})
				.on(ListTagsCommand)
				.callsFake(input => {
					// Return different tags based on the ARN
					if (input.ResourceArn === mockBackupPlanWithTags.BackupPlanArn) {
						return Promise.resolve({
							Tags: {
								Environment: "Production",
								Owner: "TeamA"
							}
						});
					}
					return Promise.resolve({ Tags: {} });
				});

			const result = await checkBackupPlanTagging.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when backup plan has no tags", async () => {
			mockBackupClient
				.on(ListBackupPlansCommand)
				.resolves({
					BackupPlansList: [mockBackupPlanWithoutTags]
				})
				.on(ListTagsCommand)
				.resolves({
					Tags: {}
				});

			const result = await checkBackupPlanTagging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Backup plan does not have any user-defined tags");
		});

		it("should return FAIL when backup plan has only system tags", async () => {
			mockBackupClient
				.on(ListBackupPlansCommand)
				.resolves({
					BackupPlansList: [mockBackupPlanWithSystemTags]
				})
				.on(ListTagsCommand)
				.resolves({
					Tags: {
						"aws:createdBy": "AWS-Service",
						"aws:backup:plan-id": "12345"
					}
				});

			const result = await checkBackupPlanTagging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Backup plan does not have any user-defined tags");
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no backup plans exist", async () => {
			mockBackupClient.on(ListBackupPlansCommand).resolves({
				BackupPlansList: []
			});

			const result = await checkBackupPlanTagging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No backup plans found in the region");
		});

		it("should return ERROR when backup plan is missing required properties", async () => {
			mockBackupClient.on(ListBackupPlansCommand).resolves({
				BackupPlansList: [{}]
			});

			const result = await checkBackupPlanTagging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Backup plan found without name or ARN");
		});

		it("should return ERROR when API call fails", async () => {
			mockBackupClient.on(ListBackupPlansCommand).rejects(new Error("API Error"));

			const result = await checkBackupPlanTagging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking backup plans: API Error");
		});
	});
});
