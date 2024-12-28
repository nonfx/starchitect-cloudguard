// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { S3Client, ListBucketsCommand, GetBucketLoggingCommand } from "@aws-sdk/client-s3";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkS3BucketLogging from "./check-s3-bucket-logging";

const mockS3Client = mockClient(S3Client);

const mockBuckets = [
	{ Name: "test-bucket-1", CreationDate: new Date() },
	{ Name: "test-bucket-2", CreationDate: new Date() }
];

describe("checkS3BucketLogging", () => {
	beforeEach(() => {
		mockS3Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when server access logging is enabled on all buckets", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockS3Client.on(GetBucketLoggingCommand).resolves({
				LoggingEnabled: {
					TargetBucket: "logging-bucket",
					TargetPrefix: "logs/"
				}
			});

			const result = await checkS3BucketLogging.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceArn).toBe("arn:aws:s3:::test-bucket-1");
		});

		it("should return NOTAPPLICABLE when no buckets exist", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [] });

			const result = await checkS3BucketLogging.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No S3 buckets found in the account");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when server access logging is disabled on buckets", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockS3Client.on(GetBucketLoggingCommand).resolves({});

			const result = await checkS3BucketLogging.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Server access logging is not enabled for this bucket");
		});

		it("should handle mixed logging configurations", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockS3Client
				.on(GetBucketLoggingCommand, { Bucket: "test-bucket-1" })
				.resolves({ LoggingEnabled: { TargetBucket: "logging-bucket" } })
				.on(GetBucketLoggingCommand, { Bucket: "test-bucket-2" })
				.resolves({});

			const result = await checkS3BucketLogging.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle buckets without names", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({
				Buckets: [{ CreationDate: new Date() }]
			});

			const result = await checkS3BucketLogging.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Bucket found without name");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListBuckets fails", async () => {
			mockS3Client.on(ListBucketsCommand).rejects(new Error("Failed to list buckets"));

			const result = await checkS3BucketLogging.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to list buckets");
		});

		it("should return ERROR for specific buckets when GetBucketLogging fails", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockS3Client.on(GetBucketLoggingCommand).rejects(new Error("Access denied"));

			const result = await checkS3BucketLogging.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking bucket logging");
		});
	});
});
