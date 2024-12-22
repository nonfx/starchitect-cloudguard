import { S3Client, ListBucketsCommand, GetBucketLifecycleConfigurationCommand } from "@aws-sdk/client-s3";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "@codegen/utils/stringUtils";
import checkS3BucketLifecycleConfiguration from "./check-s3-bucket-lifecycle-configuration";

const mockS3Client = mockClient(S3Client);

const mockBuckets = [
    { Name: "test-bucket-1", CreationDate: new Date() },
    { Name: "test-bucket-2", CreationDate: new Date() }
];

describe("checkS3BucketLifecycleConfiguration", () => {
    beforeEach(() => {
        mockS3Client.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when buckets have enabled lifecycle rules", async () => {
            mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
            mockS3Client.on(GetBucketLifecycleConfigurationCommand).resolves({
                Rules: [
                    { Status: "Enabled", ID: "Rule1" }
                ]
            });

            const result = await checkS3BucketLifecycleConfiguration();
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
        });

        it("should handle multiple lifecycle rules correctly", async () => {
            mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
            mockS3Client.on(GetBucketLifecycleConfigurationCommand).resolves({
                Rules: [
                    { Status: "Enabled", ID: "Rule1" },
                    { Status: "Disabled", ID: "Rule2" },
                    { Status: "Enabled", ID: "Rule3" }
                ]
            });

            const result = await checkS3BucketLifecycleConfiguration();
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when buckets have no enabled lifecycle rules", async () => {
            mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
            mockS3Client.on(GetBucketLifecycleConfigurationCommand).resolves({
                Rules: [
                    { Status: "Disabled", ID: "Rule1" }
                ]
            });

            const result = await checkS3BucketLifecycleConfiguration();
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("Bucket does not have any enabled lifecycle rules");
        });

        it("should return FAIL when buckets have no lifecycle configuration", async () => {
            mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
            mockS3Client.on(GetBucketLifecycleConfigurationCommand).rejects({
                name: "NoSuchLifecycleConfiguration"
            });

            const result = await checkS3BucketLifecycleConfiguration();
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("No lifecycle configuration found for the bucket");
        });

        it("should handle mixed lifecycle configurations", async () => {
            mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
            mockS3Client
                .on(GetBucketLifecycleConfigurationCommand, { Bucket: "test-bucket-1" })
                .resolves({ Rules: [{ Status: "Enabled", ID: "Rule1" }] })
                .on(GetBucketLifecycleConfigurationCommand, { Bucket: "test-bucket-2" })
                .rejects({ name: "NoSuchLifecycleConfiguration" });

            const result = await checkS3BucketLifecycleConfiguration();
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe("Error Handling", () => {
        it("should return NOTAPPLICABLE when no buckets exist", async () => {
            mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [] });

            const result = await checkS3BucketLifecycleConfiguration();
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No S3 buckets found in the account");
        });

        it("should return ERROR when ListBuckets fails", async () => {
            mockS3Client.on(ListBucketsCommand).rejects(new Error("Failed to list buckets"));

            const result = await checkS3BucketLifecycleConfiguration();
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Failed to list buckets");
        });

        it("should handle buckets without names", async () => {
            mockS3Client.on(ListBucketsCommand).resolves({
                Buckets: [{ CreationDate: new Date() }]
            });

            const result = await checkS3BucketLifecycleConfiguration();
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Bucket found without name");
        });

        it("should handle GetBucketLifecycleConfiguration errors", async () => {
            mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
            mockS3Client.on(GetBucketLifecycleConfigurationCommand).rejects(new Error("Access denied"));

            const result = await checkS3BucketLifecycleConfiguration();
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking lifecycle configuration");
        });
    });
});