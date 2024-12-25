import {
	ConfigServiceClient,
	GetResourceConfigHistoryCommand
} from "@aws-sdk/client-config-service";
import { mockClient } from "aws-sdk-client-mock";
import checkSecurityHubEnabled from "./check-security-hub";
import { ComplianceStatus } from "~runtime/types";

const mockConfigServiceClient = mockClient(ConfigServiceClient);

describe("checkSecurityHubEnabled", () => {
	beforeEach(() => {
		mockConfigServiceClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Security Hub is enabled and active", async () => {
			mockConfigServiceClient.on(GetResourceConfigHistoryCommand).resolves({
				configurationItems: [
					{
						configurationStateId: "Active",
						arn: "arn:aws:securityhub:us-east-1:123456789012:hub/default"
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
			mockConfigServiceClient.on(GetResourceConfigHistoryCommand).resolves({
				configurationItems: [
					{
						configurationStateId: "Inactive",
						arn: "arn:aws:securityhub:us-east-1:123456789012:hub/default"
					}
				]
			});

			const result = await checkSecurityHubEnabled.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Security Hub is disabled");
		});

		it("should return FAIL when Security Hub is not configured", async () => {
			mockConfigServiceClient.on(GetResourceConfigHistoryCommand).resolves({
				configurationItems: []
			});

			const result = await checkSecurityHubEnabled.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Security Hub is not configured in this region");
		});

		it("should return FAIL when Security Hub resource is not found", async () => {
			mockConfigServiceClient.on(GetResourceConfigHistoryCommand).rejects({
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
			mockConfigServiceClient
				.on(GetResourceConfigHistoryCommand)
				.rejects(new Error("Internal Server Error"));

			const result = await checkSecurityHubEnabled.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Security Hub status");
		});

		it("should handle non-Error objects in error case", async () => {
			mockConfigServiceClient.on(GetResourceConfigHistoryCommand).rejects("String error");

			const result = await checkSecurityHubEnabled.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("String error");
		});
	});

	describe("Metadata", () => {
		it("should include correct metadata in results", async () => {
			mockConfigServiceClient.on(GetResourceConfigHistoryCommand).resolves({
				configurationItems: []
			});

			expect(checkSecurityHubEnabled.title).toBe("Ensure AWS Security Hub is enabled");
			expect(checkSecurityHubEnabled.controls).toHaveLength(1);
			expect(checkSecurityHubEnabled.controls[0].id).toBe(
				"CIS-AWS-Foundations-Benchmark_v3.0.0_4.16"
			);
		});
	});
});
