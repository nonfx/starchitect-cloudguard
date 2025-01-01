// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { SecurityHubClient, GetEnabledStandardsCommand } from "@aws-sdk/client-securityhub";
import { mockClient } from "aws-sdk-client-mock";
import checkSecurityHubEnabled from "./check-security-hub";
import { ComplianceStatus } from "../../types.js";

const mockSecurityHubClient = mockClient(SecurityHubClient);

describe("checkSecurityHubEnabled", () => {
	beforeEach(() => {
		mockSecurityHubClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Security Hub is enabled and active", async () => {
			mockSecurityHubClient.on(GetEnabledStandardsCommand).resolves({
				StandardsSubscriptions: [
					{
						StandardsArn: "arn:aws:securityhub:us-east-1:123456789012:security-control/v1.0.0/IAM.1"
					}
				]
			});

			const result = await checkSecurityHubEnabled.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toBe("Security Hub is enabled");
			expect(result.checks[0].resourceArn).toBeDefined();
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when Security Hub is disabled", async () => {
			mockSecurityHubClient.on(GetEnabledStandardsCommand).resolves({
				StandardsSubscriptions: []
			});

			const result = await checkSecurityHubEnabled.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Security Hub is not enabled in this region");
		});

		it("should return FAIL when Security Hub is not configured", async () => {
			mockSecurityHubClient.on(GetEnabledStandardsCommand).resolves({
				StandardsSubscriptions: []
			});

			const result = await checkSecurityHubEnabled.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Security Hub is not enabled in this region");
		});

		it("should return FAIL when Security Hub resource is not found", async () => {
			mockSecurityHubClient.on(GetEnabledStandardsCommand).rejects({
				name: "ResourceNotFoundException",
				message: "Resource not found"
			});

			const result = await checkSecurityHubEnabled.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Security Hub is not enabled in this region");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails with unknown error", async () => {
			mockSecurityHubClient
				.on(GetEnabledStandardsCommand)
				.rejects(new Error("Internal Server Error"));

			const result = await checkSecurityHubEnabled.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Security Hub status");
		});

		it("should handle non-Error objects in error case", async () => {
			mockSecurityHubClient.on(GetEnabledStandardsCommand).rejects("String error");

			const result = await checkSecurityHubEnabled.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("String error");
		});
	});

	describe("Metadata", () => {
		it("should include correct metadata in results", async () => {
			mockSecurityHubClient.on(GetEnabledStandardsCommand).resolves({
				StandardsSubscriptions: []
			});

			expect(checkSecurityHubEnabled.title).toBe("Ensure AWS Security Hub is enabled");
			expect(checkSecurityHubEnabled.controls).toHaveLength(1);
			expect(checkSecurityHubEnabled.controls[0].id).toBe(
				"CIS-AWS-Foundations-Benchmark_v3.0.0_4.16"
			);
		});
	});
});
