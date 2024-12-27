// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { KMSClient, ListKeysCommand, DescribeKeyCommand } from "@aws-sdk/client-kms";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types";
import checkKmsKeysDeletionStatus from "./check-kms-keys-deletion-status";

const mockKmsClient = mockClient(KMSClient);

const mockKeys = [
	{ KeyId: "key-1", KeyArn: "arn:aws:kms:us-east-1:123456789012:key/key-1" },
	{ KeyId: "key-2", KeyArn: "arn:aws:kms:us-east-1:123456789012:key/key-2" }
];

describe("checkKmsKeysDeletionStatus", () => {
	beforeEach(() => {
		mockKmsClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for keys not scheduled for deletion", async () => {
			mockKmsClient.on(ListKeysCommand).resolves({ Keys: mockKeys });
			mockKmsClient.on(DescribeKeyCommand).resolves({
				KeyMetadata: {
					KeyId: "key-1",
					Arn: "arn:aws:kms:us-east-1:123456789012:key/key-1",
					DeletionDate: undefined
				}
			});

			const result = await checkKmsKeysDeletionStatus.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("key-1");
		});

		it("should return NOTAPPLICABLE when no keys exist", async () => {
			mockKmsClient.on(ListKeysCommand).resolves({ Keys: [] });

			const result = await checkKmsKeysDeletionStatus.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No KMS keys found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for keys scheduled for deletion", async () => {
			const deletionDate = new Date("2024-01-01");
			mockKmsClient.on(ListKeysCommand).resolves({ Keys: mockKeys });
			mockKmsClient.on(DescribeKeyCommand).resolves({
				KeyMetadata: {
					KeyId: "key-1",
					Arn: "arn:aws:kms:us-east-1:123456789012:key/key-1",
					DeletionDate: deletionDate
				}
			});

			const result = await checkKmsKeysDeletionStatus.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("scheduled for deletion");
		});

		it("should handle mixed deletion status scenarios", async () => {
			mockKmsClient.on(ListKeysCommand).resolves({ Keys: mockKeys });
			mockKmsClient
				.on(DescribeKeyCommand, { KeyId: "key-1" })
				.resolves({
					KeyMetadata: {
						KeyId: "key-1",
						Arn: "arn:aws:kms:us-east-1:123456789012:key/key-1",
						DeletionDate: new Date("2024-01-01")
					}
				})
				.on(DescribeKeyCommand, { KeyId: "key-2" })
				.resolves({
					KeyMetadata: {
						KeyId: "key-2",
						Arn: "arn:aws:kms:us-east-1:123456789012:key/key-2",
						DeletionDate: undefined
					}
				});

			const result = await checkKmsKeysDeletionStatus.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListKeys fails", async () => {
			mockKmsClient.on(ListKeysCommand).rejects(new Error("API Error"));

			const result = await checkKmsKeysDeletionStatus.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking KMS keys");
		});

		it("should handle keys without KeyId", async () => {
			mockKmsClient.on(ListKeysCommand).resolves({
				Keys: [{ KeyArn: "arn:aws:kms:us-east-1:123456789012:key/key-1" }]
			});

			const result = await checkKmsKeysDeletionStatus.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("KMS key found without Key ID");
		});

		it("should handle DescribeKey failures", async () => {
			mockKmsClient.on(ListKeysCommand).resolves({ Keys: mockKeys });
			mockKmsClient.on(DescribeKeyCommand).rejects(new Error("Access Denied"));

			const result = await checkKmsKeysDeletionStatus.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking key details");
		});
	});

	describe("Pagination", () => {
		it("should handle paginated results", async () => {
			mockKmsClient
				.on(ListKeysCommand)
				.resolvesOnce({
					Keys: [mockKeys[0]],
					NextMarker: "token1"
				})
				.resolvesOnce({
					Keys: [mockKeys[1]]
				});

			mockKmsClient.on(DescribeKeyCommand).resolves({
				KeyMetadata: {
					KeyId: "key-1",
					Arn: "arn:aws:kms:us-east-1:123456789012:key/key-1",
					DeletionDate: undefined
				}
			});

			const result = await checkKmsKeysDeletionStatus.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
		});
	});
});
