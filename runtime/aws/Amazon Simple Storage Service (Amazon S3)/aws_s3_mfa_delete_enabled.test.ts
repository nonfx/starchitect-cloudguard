import { S3Client, GetBucketVersioningCommand, ListBucketsCommand } from "@aws-sdk/client-s3";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkS3MfaDelete from "./aws_s3_mfa_delete_enabled";

const mockS3Client = mockClient(S3Client);

const mockBuckets = [
	{ Name: "test-bucket-1", CreationDate: new Date() },
	{ Name: "test-bucket-2", CreationDate: new Date() }
];

describe("checkS3MfaDelete", () => {
	beforeEach(() => {
		mockS3Client.reset();
	});

	it("should return PASS when MFA Delete is enabled", async () => {
		mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
		mockS3Client.on(GetBucketVersioningCommand).resolves({ MFADelete: "Enabled" });

		const result = await checkS3MfaDelete.execute();
		expect(result.checks).toHaveLength(2);
		expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
	});

	it("should return FAIL when MFA Delete is disabled", async () => {
		mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
		mockS3Client.on(GetBucketVersioningCommand).resolves({ MFADelete: "Disabled" });

		const result = await checkS3MfaDelete.execute();
		expect(result.checks).toHaveLength(2);
		expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		expect(result.checks[0].message).toBe("MFA Delete is not enabled on this bucket");
	});

	it("should handle mixed MFA Delete configurations", async () => {
		mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
		mockS3Client
			.on(GetBucketVersioningCommand)
			.resolves({ MFADelete: "Enabled" })
			.on(GetBucketVersioningCommand, { Bucket: "test-bucket-2" })
			.resolves({ MFADelete: "Disabled" });

		const result = await checkS3MfaDelete.execute();
		expect(result.checks).toHaveLength(2);
		expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
	});

	it("should return NOTAPPLICABLE for no buckets", async () => {
		mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [] });

		const result = await checkS3MfaDelete.execute();
		expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		expect(result.checks[0].message).toBe("No S3 buckets found in the account");
	});

	it("should handle API errors", async () => {
		mockS3Client.on(ListBucketsCommand).rejects(new Error("API Error"));

		const result = await checkS3MfaDelete.execute();
		expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
		expect(result.checks[0].message).toContain("API Error");
	});
});
