// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import {
	S3Client,
	ListBucketsCommand,
	GetBucketOwnershipControlsCommand
} from "@aws-sdk/client-s3";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkS3BucketAclCompliance from "./check-s3-bucket-acl-compliance";

const mockS3Client = mockClient(S3Client);

const mockBuckets = [
	{ Name: "test-bucket-1", CreationDate: new Date() },
	{ Name: "test-bucket-2", CreationDate: new Date() },
	{ Name: "test-bucket-3", CreationDate: new Date() }
];

describe("checkS3BucketAclCompliance", () => {
	beforeEach(() => {
		mockS3Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when bucket has BucketOwnerEnforced ownership", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
			mockS3Client.on(GetBucketOwnershipControlsCommand).resolves({
				OwnershipControls: {
					Rules: [{ ObjectOwnership: "BucketOwnerEnforced" }]
				}
			});

			const result = await checkS3BucketAclCompliance.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-bucket-1");
			expect(result.checks[0].resourceArn).toBe("arn:aws:s3:::test-bucket-1");
		});

		it("should return NOTAPPLICABLE when no buckets exist", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [] });

			const result = await checkS3BucketAclCompliance.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No S3 buckets found in the account");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when bucket has non-enforced ownership", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
			mockS3Client.on(GetBucketOwnershipControlsCommand).resolves({
				OwnershipControls: {
					Rules: [{ ObjectOwnership: "BucketOwnerPreferred" }]
				}
			});

			const result = await checkS3BucketAclCompliance.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Bucket does not have ACLs disabled (ObjectOwnership is not set to BucketOwnerEnforced)"
			);
		});

		it("should return FAIL when bucket has no ownership controls", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
			mockS3Client.on(GetBucketOwnershipControlsCommand).rejects({
				name: "NoSuchOwnershipControls"
			});

			const result = await checkS3BucketAclCompliance.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Bucket does not have ownership controls configured");
		});

		it("should handle multiple buckets with mixed compliance", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockS3Client
				.on(GetBucketOwnershipControlsCommand, { Bucket: "test-bucket-1" })
				.resolves({
					OwnershipControls: {
						Rules: [{ ObjectOwnership: "BucketOwnerEnforced" }]
					}
				})
				.on(GetBucketOwnershipControlsCommand, { Bucket: "test-bucket-2" })
				.resolves({
					OwnershipControls: {
						Rules: [{ ObjectOwnership: "BucketOwnerPreferred" }]
					}
				})
				.on(GetBucketOwnershipControlsCommand, { Bucket: "test-bucket-3" })
				.rejects({ name: "NoSuchOwnershipControls" });

			const result = await checkS3BucketAclCompliance.execute();
			expect(result.checks).toHaveLength(3);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[2].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListBuckets fails", async () => {
			mockS3Client.on(ListBucketsCommand).rejects(new Error("Access denied"));

			const result = await checkS3BucketAclCompliance.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking S3 buckets: Access denied");
		});

		it("should return ERROR when bucket has no name", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({
				Buckets: [{ CreationDate: new Date() }]
			});

			const result = await checkS3BucketAclCompliance.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Bucket found without name");
		});

		it("should return ERROR when GetBucketOwnershipControls fails with unexpected error", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
			mockS3Client
				.on(GetBucketOwnershipControlsCommand)
				.rejects(new Error("Internal server error"));

			const result = await checkS3BucketAclCompliance.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain(
				"Error checking bucket ownership controls: Internal server error"
			);
		});
	});
});
