import { KMSClient, ListKeysCommand, GetKeyPolicyCommand } from "@aws-sdk/client-kms";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkKmsPublicAccess from "./check-kms-public-access";

const mockKmsClient = mockClient(KMSClient);

const mockKeys = [{ KeyId: "key-1" }, { KeyId: "key-2" }, { KeyId: "key-3" }];

const mockPublicPolicy = {
	Policy: JSON.stringify({
		Statement: [
			{
				Effect: "Allow",
				Principal: {
					AWS: "*"
				}
			}
		]
	})
};

const mockPrivatePolicy = {
	Policy: JSON.stringify({
		Statement: [
			{
				Effect: "Allow",
				Principal: {
					AWS: "arn:aws:iam::123456789012:root"
				}
			}
		]
	})
};

describe("checkKmsPublicAccess", () => {
	beforeEach(() => {
		mockKmsClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for keys with private policies", async () => {
			mockKmsClient.on(ListKeysCommand).resolves({ Keys: [mockKeys[0]] });
			mockKmsClient.on(GetKeyPolicyCommand).resolves(mockPrivatePolicy);

			const result = await checkKmsPublicAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("key-1");
		});

		it("should handle multiple private keys correctly", async () => {
			mockKmsClient.on(ListKeysCommand).resolves({ Keys: mockKeys });
			mockKmsClient.on(GetKeyPolicyCommand).resolves(mockPrivatePolicy);

			const result = await checkKmsPublicAccess.execute("us-east-1");
			expect(result.checks).toHaveLength(3);
			result.checks.forEach(check => {
				expect(check.status).toBe(ComplianceStatus.PASS);
			});
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for keys with public policies", async () => {
			mockKmsClient.on(ListKeysCommand).resolves({ Keys: [mockKeys[0]] });
			mockKmsClient.on(GetKeyPolicyCommand).resolves(mockPublicPolicy);

			const result = await checkKmsPublicAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("KMS key policy allows public access");
		});

		it("should handle mixed policy configurations", async () => {
			mockKmsClient.on(ListKeysCommand).resolves({ Keys: mockKeys.slice(0, 2) });
			mockKmsClient
				.on(GetKeyPolicyCommand, { KeyId: "key-1" })
				.resolves(mockPublicPolicy)
				.on(GetKeyPolicyCommand, { KeyId: "key-2" })
				.resolves(mockPrivatePolicy);

			const result = await checkKmsPublicAccess.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no keys exist", async () => {
			mockKmsClient.on(ListKeysCommand).resolves({ Keys: [] });

			const result = await checkKmsPublicAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No KMS keys found in the region");
		});

		it("should handle ListKeys API errors", async () => {
			mockKmsClient.on(ListKeysCommand).rejects(new Error("API Error"));

			const result = await checkKmsPublicAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking KMS keys");
		});

		it("should handle GetKeyPolicy API errors", async () => {
			mockKmsClient.on(ListKeysCommand).resolves({ Keys: [mockKeys[0]] });
			mockKmsClient.on(GetKeyPolicyCommand).rejects(new Error("Policy Error"));

			const result = await checkKmsPublicAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking key policy");
		});

		it("should handle invalid policy responses", async () => {
			mockKmsClient.on(ListKeysCommand).resolves({ Keys: [mockKeys[0]] });
			mockKmsClient.on(GetKeyPolicyCommand).resolves({ Policy: undefined });

			const result = await checkKmsPublicAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Unable to retrieve key policy");
		});
	});
});
