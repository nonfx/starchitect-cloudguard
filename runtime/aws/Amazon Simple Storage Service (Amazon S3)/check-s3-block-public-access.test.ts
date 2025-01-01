// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { S3Client, GetPublicAccessBlockCommand, ListBucketsCommand } from "@aws-sdk/client-s3";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkS3BlockPublicAccess from "./check-s3-block-public-access";

const mockS3Client = mockClient(S3Client);

const mockBuckets = [
	{ Name: "test-bucket-1", CreationDate: new Date() },
	{ Name: "test-bucket-2", CreationDate: new Date() }
];

const compliantBlockConfig = {
	PublicAccessBlockConfiguration: {
		BlockPublicAcls: true,
		BlockPublicPolicy: true,
		IgnorePublicAcls: true,
		RestrictPublicBuckets: true
	}
};

const nonCompliantBlockConfig = {
	PublicAccessBlockConfiguration: {
		BlockPublicAcls: true,
		BlockPublicPolicy: false,
		IgnorePublicAcls: true,
		RestrictPublicBuckets: false
	}
};

describe("checkS3BlockPublicAccess", () => {
	beforeEach(() => {
		mockS3Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when all buckets have complete public access blocking", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockS3Client.on(GetPublicAccessBlockCommand).resolves(compliantBlockConfig);

			const result = await checkS3BlockPublicAccess.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});

		it("should return NOTAPPLICABLE when no buckets exist", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [] });

			const result = await checkS3BlockPublicAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No S3 buckets found in the account");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when buckets have incomplete public access blocking", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockS3Client.on(GetPublicAccessBlockCommand).resolves(nonCompliantBlockConfig);

			const result = await checkS3BlockPublicAccess.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Bucket does not have all public access block settings enabled"
			);
		});

		it("should return FAIL when buckets have no public access block configuration", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockS3Client.on(GetPublicAccessBlockCommand).rejects({
				name: "NoSuchPublicAccessBlockConfiguration"
			});

			const result = await checkS3BlockPublicAccess.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No public access block configuration found for bucket"
			);
		});

		it("should handle mixed compliance scenarios", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockS3Client
				.on(GetPublicAccessBlockCommand, { Bucket: "test-bucket-1" })
				.resolves(compliantBlockConfig)
				.on(GetPublicAccessBlockCommand, { Bucket: "test-bucket-2" })
				.resolves(nonCompliantBlockConfig);

			const result = await checkS3BlockPublicAccess.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListBuckets fails", async () => {
			mockS3Client.on(ListBucketsCommand).rejects(new Error("Failed to list buckets"));

			const result = await checkS3BlockPublicAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to list buckets");
		});

		it("should return ERROR when GetPublicAccessBlock fails with unexpected error", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockS3Client.on(GetPublicAccessBlockCommand).rejects(new Error("Access denied"));

			const result = await checkS3BlockPublicAccess.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking bucket public access block");
		});
	});
});
