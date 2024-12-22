import { S3Client, GetBucketPolicyCommand, ListBucketsCommand } from "@aws-sdk/client-s3";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "@codegen/utils/stringUtils";
import checkS3DenyHttpAccess from "./check-s3-deny-http-access";

const mockS3Client = mockClient(S3Client);

const mockBuckets = [
    { Name: "test-bucket-1", CreationDate: new Date() },
    { Name: "test-bucket-2", CreationDate: new Date() }
];

const compliantPolicy = {
    Version: "2012-10-17",
    Statement: [{
        Effect: "Deny",
        Action: "s3:GetObject",
        Resource: "arn:aws:s3:::test-bucket-1/*",
        Condition: {
            Bool: {
                "aws:SecureTransport": "false"
            }
        }
    }]
};

const nonCompliantPolicy = {
    Version: "2012-10-17",
    Statement: [{
        Effect: "Allow",
        Action: "s3:GetObject",
        Resource: "arn:aws:s3:::test-bucket-2/*"
    }]
};

describe("checkS3DenyHttpAccess", () => {
    beforeEach(() => {
        mockS3Client.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when bucket policy denies HTTP access", async () => {
            mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
            mockS3Client.on(GetBucketPolicyCommand).resolves({
                Policy: JSON.stringify(compliantPolicy)
            });

            const result = await checkS3DenyHttpAccess();
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("test-bucket-1");
        });

        it("should handle multiple compliant buckets", async () => {
            mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
            mockS3Client.on(GetBucketPolicyCommand).resolves({
                Policy: JSON.stringify(compliantPolicy)
            });

            const result = await checkS3DenyHttpAccess();
            expect(result.checks).toHaveLength(2);
            expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when bucket policy doesn't deny HTTP access", async () => {
            mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[1]] });
            mockS3Client.on(GetBucketPolicyCommand).resolves({
                Policy: JSON.stringify(nonCompliantPolicy)
            });

            const result = await checkS3DenyHttpAccess();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("Bucket policy does not deny HTTP requests");
        });

        it("should return FAIL when bucket has no policy", async () => {
            mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
            mockS3Client.on(GetBucketPolicyCommand).rejects({
                name: "NoSuchBucketPolicy"
            });

            const result = await checkS3DenyHttpAccess();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("Bucket has no policy configured");
        });

        it("should handle mixed compliance scenarios", async () => {
            mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
            mockS3Client
                .on(GetBucketPolicyCommand, { Bucket: "test-bucket-1" })
                .resolves({ Policy: JSON.stringify(compliantPolicy) })
                .on(GetBucketPolicyCommand, { Bucket: "test-bucket-2" })
                .resolves({ Policy: JSON.stringify(nonCompliantPolicy) });

            const result = await checkS3DenyHttpAccess();
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe("Error Handling", () => {
        it("should return NOTAPPLICABLE when no buckets exist", async () => {
            mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [] });

            const result = await checkS3DenyHttpAccess();
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No S3 buckets found");
        });

        it("should return ERROR when ListBuckets fails", async () => {
            mockS3Client.on(ListBucketsCommand).rejects(new Error("API Error"));

            const result = await checkS3DenyHttpAccess();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking S3 buckets");
        });

        it("should return ERROR when GetBucketPolicy fails unexpectedly", async () => {
            mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
            mockS3Client.on(GetBucketPolicyCommand).rejects(new Error("Access Denied"));

            const result = await checkS3DenyHttpAccess();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking bucket policy");
        });
    });
});