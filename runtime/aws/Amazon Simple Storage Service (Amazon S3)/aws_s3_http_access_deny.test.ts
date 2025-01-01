// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { S3Client, GetBucketPolicyCommand, ListBucketsCommand } from "@aws-sdk/client-s3";
import { mockClient } from "aws-sdk-client-mock";
import checkS3DenyHttpAccess from "./aws_s3_http_access_deny";
import { ComplianceStatus } from "../../types.js";

const mockS3Client = mockClient(S3Client);

const mockBuckets = [
	{ Name: "test-bucket-1", CreationDate: new Date() },
	{ Name: "test-bucket-2", CreationDate: new Date() }
];

const validDenyHttpPolicy = {
	Version: "2012-10-17",
	Statement: [
		{
			Effect: "Deny",
			Action: "s3:GetObject",
			Resource: "arn:aws:s3:::test-bucket-1/*",
			Condition: {
				Bool: {
					"aws:SecureTransport": "false"
				}
			}
		}
	]
};

const invalidPolicy = {
	Version: "2012-10-17",
	Statement: [
		{
			Effect: "Allow",
			Action: "s3:GetObject",
			Resource: "arn:aws:s3:::test-bucket-2/*"
		}
	]
};

describe("checkS3DenyHttpAccess", () => {
	beforeEach(() => {
		mockS3Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when bucket policy denies HTTP access", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
			mockS3Client.on(GetBucketPolicyCommand).resolves({
				Policy: JSON.stringify(validDenyHttpPolicy)
			});

			const result = await checkS3DenyHttpAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-bucket-1");
		});

		it("should handle multiple statements with valid deny HTTP configuration", async () => {
			const multiStatementPolicy = {
				Version: "2012-10-17",
				Statement: [
					{ Effect: "Allow", Action: "s3:ListBucket", Resource: "*" },
					{
						Effect: "Deny",
						Action: "*",
						Resource: "*",
						Condition: { Bool: { "aws:SecureTransport": "false" } }
					}
				]
			};

			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
			mockS3Client.on(GetBucketPolicyCommand).resolves({
				Policy: JSON.stringify(multiStatementPolicy)
			});

			const result = await checkS3DenyHttpAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when bucket policy does not deny HTTP access", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[1]] });
			mockS3Client.on(GetBucketPolicyCommand).resolves({
				Policy: JSON.stringify(invalidPolicy)
			});

			const result = await checkS3DenyHttpAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Bucket policy does not deny HTTP requests");
		});

		it("should return FAIL when bucket has no policy", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
			mockS3Client.on(GetBucketPolicyCommand).rejects({
				name: "NoSuchBucketPolicy"
			});

			const result = await checkS3DenyHttpAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Bucket has no policy configured");
		});

		it("should handle mixed compliance results", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockS3Client
				.on(GetBucketPolicyCommand, { Bucket: "test-bucket-1" })
				.resolves({ Policy: JSON.stringify(validDenyHttpPolicy) })
				.on(GetBucketPolicyCommand, { Bucket: "test-bucket-2" })
				.resolves({ Policy: JSON.stringify(invalidPolicy) });

			const result = await checkS3DenyHttpAccess.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no buckets exist", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [] });

			const result = await checkS3DenyHttpAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No S3 buckets found in the account");
		});

		it("should return ERROR when ListBuckets fails", async () => {
			mockS3Client.on(ListBucketsCommand).rejects(new Error("API Error"));

			const result = await checkS3DenyHttpAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking S3 buckets");
		});

		it("should return ERROR when GetBucketPolicy fails with unexpected error", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
			mockS3Client.on(GetBucketPolicyCommand).rejects(new Error("Access Denied"));

			const result = await checkS3DenyHttpAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking bucket policy");
		});
	});
});
