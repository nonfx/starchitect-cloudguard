// @ts-nocheck
import { BackupClient, ListReportPlansCommand, ListTagsCommand } from "@aws-sdk/client-backup";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkBackupReportPlanTags from "./check-backup-report-plan-tags";

const mockBackupClient = mockClient(BackupClient);

const mockReportPlan = {
	ReportPlanName: "test-report-plan",
	ReportPlanArn: "arn:aws:backup:us-east-1:123456789012:report-plan:test-report-plan"
};

describe("checkBackupReportPlanTags", () => {
	beforeEach(() => {
		mockBackupClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when report plan has user-defined tags", async () => {
			mockBackupClient.on(ListReportPlansCommand).resolves({ ReportPlans: [mockReportPlan] });
			mockBackupClient.on(ListTagsCommand).resolves({ Tags: { "user-tag": "value" } });

			const result = await checkBackupReportPlanTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe(mockReportPlan.ReportPlanName);
			expect(result.checks[0].resourceArn).toBe(mockReportPlan.ReportPlanArn);
		});

		it("should handle multiple report plans with tags", async () => {
			const secondPlan = {
				ReportPlanName: "test-report-plan-2",
				ReportPlanArn: "arn:aws:backup:us-east-1:123456789012:report-plan:test-report-plan-2"
			};

			mockBackupClient
				.on(ListReportPlansCommand)
				.resolves({ ReportPlans: [mockReportPlan, secondPlan] });
			mockBackupClient.on(ListTagsCommand).resolves({ Tags: { "user-tag": "value" } });

			const result = await checkBackupReportPlanTags.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when report plan has no user-defined tags", async () => {
			mockBackupClient.on(ListReportPlansCommand).resolves({ ReportPlans: [mockReportPlan] });
			mockBackupClient.on(ListTagsCommand).resolves({ Tags: { "aws:created": "system" } });

			const result = await checkBackupReportPlanTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Backup report plan does not have any user-defined tags"
			);
		});

		it("should return FAIL when report plan has empty tags", async () => {
			mockBackupClient.on(ListReportPlansCommand).resolves({ ReportPlans: [mockReportPlan] });
			mockBackupClient.on(ListTagsCommand).resolves({ Tags: {} });

			const result = await checkBackupReportPlanTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no report plans exist", async () => {
			mockBackupClient.on(ListReportPlansCommand).resolves({ ReportPlans: [] });

			const result = await checkBackupReportPlanTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No backup report plans found in the region");
		});

		it("should return ERROR when ListReportPlans fails", async () => {
			mockBackupClient.on(ListReportPlansCommand).rejects(new Error("API Error"));

			const result = await checkBackupReportPlanTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking backup report plans");
		});

		it("should return ERROR when ListTags fails for a specific plan", async () => {
			mockBackupClient.on(ListReportPlansCommand).resolves({ ReportPlans: [mockReportPlan] });
			mockBackupClient.on(ListTagsCommand).rejects(new Error("Access Denied"));

			const result = await checkBackupReportPlanTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking tags");
		});

		it("should handle report plans without name or ARN", async () => {
			mockBackupClient.on(ListReportPlansCommand).resolves({ ReportPlans: [{}] });

			const result = await checkBackupReportPlanTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Report plan found without name or ARN");
		});
	});
});
