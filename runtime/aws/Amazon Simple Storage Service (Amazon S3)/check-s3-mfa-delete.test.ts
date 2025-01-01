// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { S3Client, GetBucketVersioningCommand, ListBucketsCommand } from "@aws-sdk/client-s3";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkS3MfaDelete from "./check-s3-mfa-delete";

const mockS3Client = mockClient(S3Client);

const mockBuckets = [
	{ Name: "test-bucket-1", CreationDate: new Date() },
	{ Name: "test-bucket-2", CreationDate: new Date() }
];

describe("checkS3MfaDelete", () => {
	beforeEach(() => {
		mockS3Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when MFA Delete is enabled on all buckets", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockS3Client.on(GetBucketVersioningCommand).resolves({ MFADelete: "Enabled" });

			const result = await checkS3MfaDelete.execute();
			expect(result.checks).toHaveLength(2);
			result.checks.forEach(check => {
				expect(check.status).toBe(ComplianceStatus.PASS);
				expect(check.resourceArn).toBe(`arn:aws:s3:::${check.resourceName}`);
			});
		});

		it("should return NOTAPPLICABLE when no buckets exist", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [] });

			const result = await checkS3MfaDelete.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No S3 buckets found in the account");
		});

		it("should handle buckets without names gracefully", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({
				Buckets: [{ CreationDate: new Date() }]
			});

			const result = await checkS3MfaDelete.execute();
			expect(result.checks).toHaveLength(0);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when MFA Delete is disabled on buckets", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockS3Client.on(GetBucketVersioningCommand).resolves({ MFADelete: "Disabled" });

			const result = await checkS3MfaDelete.execute();
			expect(result.checks).toHaveLength(2);
			result.checks.forEach(check => {
				expect(check.status).toBe(ComplianceStatus.FAIL);
				expect(check.message).toBe("MFA Delete is not enabled on this bucket");
			});
		});

		it("should return FAIL when MFA Delete is not configured", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockS3Client.on(GetBucketVersioningCommand).resolves({});

			const result = await checkS3MfaDelete.execute();
			expect(result.checks).toHaveLength(2);
			result.checks.forEach(check => {
				expect(check.status).toBe(ComplianceStatus.FAIL);
			});
		});

		it("should handle mixed MFA Delete configurations", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockS3Client
				.on(GetBucketVersioningCommand, { Bucket: "test-bucket-1" })
				.resolves({ MFADelete: "Enabled" })
				.on(GetBucketVersioningCommand, { Bucket: "test-bucket-2" })
				.resolves({ MFADelete: "Disabled" });

			const result = await checkS3MfaDelete.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListBuckets fails", async () => {
			mockS3Client.on(ListBucketsCommand).rejects(new Error("Failed to list buckets"));

			const result = await checkS3MfaDelete.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to list buckets");
		});

		it("should return ERROR for specific buckets when GetBucketVersioning fails", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockS3Client.on(GetBucketVersioningCommand).rejects(new Error("Access denied"));

			const result = await checkS3MfaDelete.execute();
			expect(result.checks).toHaveLength(2);
			result.checks.forEach(check => {
				expect(check.status).toBe(ComplianceStatus.ERROR);
				expect(check.message).toContain("Error checking bucket versioning");
			});
		});

		it("should handle undefined Buckets response", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({});

			const result = await checkS3MfaDelete.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});

	describe("Metadata", () => {
		it("should include correct metadata in the report", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [] });

			// const result = await checkS3MfaDelete.
			expect(checkS3MfaDelete.title).toBe("Ensure MFA Delete is enabled on S3 buckets");
			expect(checkS3MfaDelete.controls[0].id).toBe("CIS-AWS-Foundations-Benchmark_v3.0.0_2.1.2");
		});
	});
});
