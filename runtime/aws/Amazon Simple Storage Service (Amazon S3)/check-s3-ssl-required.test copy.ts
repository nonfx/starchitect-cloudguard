import { S3Client, ListBucketsCommand, GetBucketPolicyCommand } from "@aws-sdk/client-s3";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkS3SSLRequired from "./check-s3-ssl-required";

const mockS3Client = mockClient(S3Client);

const mockBuckets = [
	{ Name: "test-bucket-1", CreationDate: new Date() },
	{ Name: "test-bucket-2", CreationDate: new Date() }
];

const validSSLPolicy = {
	Version: "2012-10-17",
	Statement: [
		{
			Effect: "Deny",
			Principal: "*",
			Action: "s3:*",
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
			Principal: "*",
			Action: "s3:*",
			Resource: "arn:aws:s3:::test-bucket-2/*"
		}
	]
};

describe("checkS3SSLRequired", () => {
	beforeEach(() => {
		mockS3Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when bucket policy enforces SSL/TLS", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
			mockS3Client.on(GetBucketPolicyCommand).resolves({
				Policy: JSON.stringify(validSSLPolicy)
			});

			const result = await checkS3SSLRequired.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-bucket-1");
		});

		it("should handle multiple buckets with valid SSL policies", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockS3Client.on(GetBucketPolicyCommand).resolves({
				Policy: JSON.stringify(validSSLPolicy)
			});

			const result = await checkS3SSLRequired.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when bucket policy doesn't enforce SSL/TLS", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
			mockS3Client.on(GetBucketPolicyCommand).resolves({
				Policy: JSON.stringify(invalidPolicy)
			});

			const result = await checkS3SSLRequired.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Bucket policy does not enforce SSL/TLS using aws:SecureTransport condition"
			);
		});

		it("should return FAIL when bucket has no policy", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
			mockS3Client.on(GetBucketPolicyCommand).rejects({
				name: "NoSuchBucketPolicy"
			});

			const result = await checkS3SSLRequired.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No bucket policy exists to enforce SSL/TLS");
		});

		it("should handle mixed compliance results", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockS3Client
				.on(GetBucketPolicyCommand, { Bucket: "test-bucket-1" })
				.resolves({ Policy: JSON.stringify(validSSLPolicy) })
				.on(GetBucketPolicyCommand, { Bucket: "test-bucket-2" })
				.resolves({ Policy: JSON.stringify(invalidPolicy) });

			const result = await checkS3SSLRequired.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no buckets exist", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [] });

			const result = await checkS3SSLRequired.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No S3 buckets found in the account");
		});

		it("should return ERROR when ListBuckets fails", async () => {
			mockS3Client.on(ListBucketsCommand).rejects(new Error("API Error"));

			const result = await checkS3SSLRequired.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking S3 buckets");
		});

		it("should return ERROR when GetBucketPolicy fails with unexpected error", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
			mockS3Client.on(GetBucketPolicyCommand).rejects(new Error("Access Denied"));

			const result = await checkS3SSLRequired.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking bucket policy");
		});
	});
});
