// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import {
	KMSClient,
	ListKeysCommand,
	GetKeyRotationStatusCommand,
	DescribeKeyCommand
} from "@aws-sdk/client-kms";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkKmsKeyRotation from "./check-kms-key-rotation";

const mockKmsClient = mockClient(KMSClient);

const mockCustomerManagedKey = {
	KeyId: "12345678-1234-1234-1234-123456789012",
	Arn: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
	KeyManager: "CUSTOMER",
	KeySpec: "SYMMETRIC_DEFAULT"
};

const mockAwsManagedKey = {
	KeyId: "98765432-9876-9876-9876-987654321098",
	Arn: "arn:aws:kms:us-east-1:123456789012:key/98765432-9876-9876-9876-987654321098",
	KeyManager: "AWS",
	KeySpec: "SYMMETRIC_DEFAULT"
};

const mockAsymmetricKey = {
	KeyId: "11111111-1111-1111-1111-111111111111",
	Arn: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111",
	KeyManager: "CUSTOMER",
	KeySpec: "RSA_2048"
};

describe("checkKmsKeyRotation", () => {
	beforeEach(() => {
		mockKmsClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when key rotation is enabled for customer-managed symmetric keys", async () => {
			mockKmsClient
				.on(ListKeysCommand)
				.resolves({ Keys: [{ KeyId: mockCustomerManagedKey.KeyId }] });
			mockKmsClient.on(DescribeKeyCommand).resolves({ KeyMetadata: mockCustomerManagedKey });
			mockKmsClient.on(GetKeyRotationStatusCommand).resolves({ KeyRotationEnabled: true });

			const result = await checkKmsKeyRotation.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe(mockCustomerManagedKey.KeyId);
			expect(result.checks[0].resourceArn).toBe(mockCustomerManagedKey.Arn);
		});

		it("should skip AWS managed keys", async () => {
			mockKmsClient.on(ListKeysCommand).resolves({ Keys: [{ KeyId: mockAwsManagedKey.KeyId }] });
			mockKmsClient.on(DescribeKeyCommand).resolves({ KeyMetadata: mockAwsManagedKey });

			const result = await checkKmsKeyRotation.execute("us-east-1");
			expect(result.checks).toHaveLength(0);
		});

		it("should skip asymmetric keys", async () => {
			mockKmsClient.on(ListKeysCommand).resolves({ Keys: [{ KeyId: mockAsymmetricKey.KeyId }] });
			mockKmsClient.on(DescribeKeyCommand).resolves({ KeyMetadata: mockAsymmetricKey });

			const result = await checkKmsKeyRotation.execute("us-east-1");
			expect(result.checks).toHaveLength(0);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when key rotation is disabled", async () => {
			mockKmsClient
				.on(ListKeysCommand)
				.resolves({ Keys: [{ KeyId: mockCustomerManagedKey.KeyId }] });
			mockKmsClient.on(DescribeKeyCommand).resolves({ KeyMetadata: mockCustomerManagedKey });
			mockKmsClient.on(GetKeyRotationStatusCommand).resolves({ KeyRotationEnabled: false });

			const result = await checkKmsKeyRotation.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Key rotation is not enabled");
		});

		it("should handle mixed rotation status for multiple keys", async () => {
			const secondKey = { ...mockCustomerManagedKey, KeyId: "second-key-id" };
			mockKmsClient
				.on(ListKeysCommand)
				.resolves({ Keys: [{ KeyId: mockCustomerManagedKey.KeyId }, { KeyId: secondKey.KeyId }] });
			mockKmsClient.on(DescribeKeyCommand).resolves({ KeyMetadata: mockCustomerManagedKey });
			mockKmsClient
				.on(GetKeyRotationStatusCommand)
				.resolves({ KeyRotationEnabled: true })
				.on(GetKeyRotationStatusCommand, { KeyId: secondKey.KeyId })
				.resolves({ KeyRotationEnabled: false });

			const result = await checkKmsKeyRotation.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no keys exist", async () => {
			mockKmsClient.on(ListKeysCommand).resolves({ Keys: [] });

			const result = await checkKmsKeyRotation.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No KMS keys found in the region");
		});

		it("should return ERROR when ListKeys fails", async () => {
			mockKmsClient.on(ListKeysCommand).rejects(new Error("Failed to list keys"));

			const result = await checkKmsKeyRotation.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to list keys");
		});

		it("should handle pagination", async () => {
			mockKmsClient
				.on(ListKeysCommand)
				.resolvesOnce({
					Keys: [{ KeyId: mockCustomerManagedKey.KeyId }],
					NextMarker: "next-page"
				})
				.resolvesOnce({
					Keys: [{ KeyId: "second-key-id" }]
				});
			mockKmsClient.on(DescribeKeyCommand).resolves({ KeyMetadata: mockCustomerManagedKey });
			mockKmsClient.on(GetKeyRotationStatusCommand).resolves({ KeyRotationEnabled: true });

			const result = await checkKmsKeyRotation.execute("us-east-1");
			expect(result.checks.length).toBeGreaterThan(1);
		});
	});
});
