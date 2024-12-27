// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { S3Client, GetBucketPolicyCommand, ListBucketsCommand } from "@aws-sdk/client-s3";
import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkS3BucketExternalAccess from "./check-s3-bucket-external-access";

const mockS3Client = mockClient(S3Client);
const mockSTSClient = mockClient(STSClient);

const MOCK_ACCOUNT_ID = "123456789012";
const EXTERNAL_ACCOUNT_ID = "999999999999";
const MOCK_BUCKETS = [
	{ Name: "test-bucket-1", CreationDate: new Date() },
	{ Name: "test-bucket-2", CreationDate: new Date() }
];

describe("checkS3BucketExternalAccess", () => {
	beforeEach(() => {
		mockS3Client.reset();
		mockSTSClient.reset();
		// Set default STS response
		mockSTSClient.on(GetCallerIdentityCommand).resolves({
			Account: MOCK_ACCOUNT_ID
		});
	});

	describe("Compliant Resources", () => {
		it("should return PASS for bucket with no policy", async () => {
			mockS3Client
				.on(ListBucketsCommand)
				.resolves({ Buckets: [MOCK_BUCKETS[0]] })
				.on(GetBucketPolicyCommand)
				.rejects({ name: "NoSuchBucketPolicy" });

			const result = await checkS3BucketExternalAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toBe("Bucket has no policy attached");
		});

		it("should return PASS for bucket with safe policy", async () => {
			const safePolicy = {
				Version: "2012-10-17",
				Statement: [
					{
						Effect: "Allow",
						Principal: {
							AWS: `arn:aws:iam::${MOCK_ACCOUNT_ID}:root`
						},
						Action: ["s3:GetObject"],
						Resource: ["arn:aws:s3:::test-bucket-1/*"]
					}
				]
			};

			mockS3Client
				.on(ListBucketsCommand)
				.resolves({ Buckets: [MOCK_BUCKETS[0]] })
				.on(GetBucketPolicyCommand)
				.resolves({ Policy: JSON.stringify(safePolicy) });

			const result = await checkS3BucketExternalAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});

		it("should return PASS for bucket with external access but proper source account", async () => {
			const safePolicy = {
				Version: "2012-10-17",
				Statement: [
					{
						Effect: "Allow",
						Principal: {
							Service: "logging.s3.amazonaws.com"
						},
						Action: ["s3:PutObject"],
						Resource: ["arn:aws:s3:::test-bucket-1/*"],
						Condition: {
							StringEquals: {
								"aws:SourceAccount": MOCK_ACCOUNT_ID
							}
						}
					}
				]
			};

			mockS3Client
				.on(ListBucketsCommand)
				.resolves({ Buckets: [MOCK_BUCKETS[0]] })
				.on(GetBucketPolicyCommand)
				.resolves({ Policy: JSON.stringify(safePolicy) });

			const result = await checkS3BucketExternalAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for bucket with risky external access", async () => {
			const riskyPolicy = {
				Version: "2012-10-17",
				Statement: [
					{
						Effect: "Allow",
						Principal: {
							AWS: "arn:aws:iam::999999999999:root"
						},
						Action: ["s3:PutBucketPolicy", "s3:GetObject"],
						Resource: ["arn:aws:s3:::test-bucket-1/*"],
						Condition: {
							StringEquals: {
								"aws:SourceAccount": EXTERNAL_ACCOUNT_ID
							}
						}
					}
				]
			};

			mockS3Client
				.on(ListBucketsCommand)
				.resolves({ Buckets: [MOCK_BUCKETS[0]] })
				.on(GetBucketPolicyCommand)
				.resolves({ Policy: JSON.stringify(riskyPolicy) });

			const result = await checkS3BucketExternalAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Bucket policy allows blacklisted actions without proper account restrictions"
			);
		});

		it("should handle multiple statements with mixed permissions", async () => {
			const mixedPolicy = {
				Version: "2012-10-17",
				Statement: [
					{
						Effect: "Allow",
						Principal: {
							AWS: `arn:aws:iam::${MOCK_ACCOUNT_ID}:root`
						},
						Action: ["s3:GetObject"],
						Resource: ["arn:aws:s3:::test-bucket-1/*"]
					},
					{
						Effect: "Allow",
						Principal: {
							AWS: "arn:aws:iam::999999999999:root"
						},
						Action: ["s3:PutBucketAcl"],
						Resource: ["arn:aws:s3:::test-bucket-1/*"],
						Condition: {
							StringEquals: {
								"aws:SourceAccount": EXTERNAL_ACCOUNT_ID
							}
						}
					}
				]
			};

			mockS3Client
				.on(ListBucketsCommand)
				.resolves({ Buckets: [MOCK_BUCKETS[0]] })
				.on(GetBucketPolicyCommand)
				.resolves({ Policy: JSON.stringify(mixedPolicy) });

			const result = await checkS3BucketExternalAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no buckets exist", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [] });

			const result = await checkS3BucketExternalAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No S3 buckets found in the account");
		});

		it("should return ERROR when STS call fails", async () => {
			mockSTSClient.on(GetCallerIdentityCommand).rejects(new Error("STS Error"));

			const result = await checkS3BucketExternalAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking S3 buckets");
		});

		it("should return ERROR when bucket policy check fails", async () => {
			mockS3Client
				.on(ListBucketsCommand)
				.resolves({ Buckets: [MOCK_BUCKETS[0]] })
				.on(GetBucketPolicyCommand)
				.rejects(new Error("Access Denied"));

			const result = await checkS3BucketExternalAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking bucket policy");
		});
	});
});
