import {
	CloudTrailClient,
	GetTrailCommand,
	ListTrailsCommand,
	GetEventSelectorsCommand
} from "@aws-sdk/client-cloudtrail";
import { S3Client, ListBucketsCommand } from "@aws-sdk/client-s3";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "@codegen/utils/stringUtils";
import checkS3ObjectLevelLogging from "./check-s3-object-level-logging";

const mockCloudTrailClient = mockClient(CloudTrailClient);
const mockS3Client = mockClient(S3Client);

const mockBuckets = [
	{ Name: "test-bucket-1", CreationDate: new Date() },
	{ Name: "test-bucket-2", CreationDate: new Date() }
];

const mockTrailWithWriteLogging = {
	Name: "trail-with-logging",
	TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/trail-with-logging"
};

const mockTrailWithAllLogging = {
	Name: "trail-all-logging",
	TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/trail-all-logging"
};

describe("checkS3ObjectLevelLogging", () => {
	beforeEach(() => {
		mockCloudTrailClient.reset();
		mockS3Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when bucket has write-only logging enabled", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({
					Trails: [{ Name: mockTrailWithWriteLogging.Name }]
				})
				.on(GetTrailCommand)
				.resolves({ Trail: mockTrailWithWriteLogging })
				.on(GetEventSelectorsCommand)
				.resolves({
					EventSelectors: [
						{
							ReadWriteType: "WriteOnly",
							DataResources: [
								{
									Type: "AWS::S3::Object",
									Values: ["arn:aws:s3:::test-bucket-1/"]
								}
							]
						}
					]
				});

			const result = await checkS3ObjectLevelLogging();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-bucket-1");
		});

		it("should return PASS when bucket is covered by all-logging trail", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({
					Trails: [{ Name: mockTrailWithAllLogging.Name }]
				})
				.on(GetTrailCommand)
				.resolves({ Trail: mockTrailWithAllLogging })
				.on(GetEventSelectorsCommand)
				.resolves({
					EventSelectors: [
						{
							ReadWriteType: "All",
							DataResources: [
								{
									Type: "AWS::S3::Object",
									Values: ["arn:aws:s3"]
								}
							]
						}
					]
				});

			const result = await checkS3ObjectLevelLogging();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});

		it("should return PASS with advanced event selectors", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({
					Trails: [{ Name: mockTrailWithWriteLogging.Name }]
				})
				.on(GetTrailCommand)
				.resolves({ Trail: mockTrailWithWriteLogging })
				.on(GetEventSelectorsCommand)
				.resolves({
					AdvancedEventSelectors: [
						{
							FieldSelectors: [
								{ Field: "readOnly", Equals: ["false"] },
								{ Field: "eventCategory", Equals: ["Data"] },
								{ Field: "resources.type", Equals: ["AWS::S3::Object"] },
								{
									Field: "resources.ARN",
									StartsWith: ["arn:aws:s3:::test-bucket-1/"]
								}
							]
						}
					]
				});

			const result = await checkS3ObjectLevelLogging();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when bucket has no logging enabled", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockCloudTrailClient.on(ListTrailsCommand).resolves({ Trails: [] });

			const result = await checkS3ObjectLevelLogging();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.FAIL)).toBe(true);
			expect(result.checks[0].message).toContain("does not have object-level logging enabled");
		});

		it("should return FAIL when trail has incorrect ReadWriteType", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({
					Trails: [{ Name: mockTrailWithWriteLogging.Name }]
				})
				.on(GetTrailCommand)
				.resolves({ Trail: mockTrailWithWriteLogging })
				.on(GetEventSelectorsCommand)
				.resolves({
					EventSelectors: [
						{
							ReadWriteType: "ReadOnly",
							DataResources: [
								{
									Type: "AWS::S3::Object",
									Values: ["arn:aws:s3:::test-bucket-1/"]
								}
							]
						}
					]
				});

			const result = await checkS3ObjectLevelLogging();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});

		it("should return FAIL with incomplete advanced event selectors", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({
					Trails: [{ Name: mockTrailWithWriteLogging.Name }]
				})
				.on(GetTrailCommand)
				.resolves({ Trail: mockTrailWithWriteLogging })
				.on(GetEventSelectorsCommand)
				.resolves({
					AdvancedEventSelectors: [
						{
							FieldSelectors: [
								{ Field: "eventCategory", Equals: ["Data"] },
								{ Field: "resources.type", Equals: ["AWS::S3::Object"] }
								// Missing readOnly field
							]
						}
					]
				});

			const result = await checkS3ObjectLevelLogging();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no buckets exist", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [] });

			const result = await checkS3ObjectLevelLogging();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No S3 buckets found");
		});

		it("should handle pagination in CloudTrail listing", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolvesOnce({
					Trails: [{ Name: mockTrailWithWriteLogging.Name }],
					NextToken: "token1"
				})
				.resolvesOnce({
					Trails: [{ Name: mockTrailWithAllLogging.Name }]
				})
				.on(GetTrailCommand)
				.resolves({ Trail: mockTrailWithWriteLogging })
				.on(GetEventSelectorsCommand)
				.resolves({
					EventSelectors: [
						{
							ReadWriteType: "WriteOnly",
							DataResources: [
								{
									Type: "AWS::S3::Object",
									Values: ["arn:aws:s3:::test-bucket-1/"]
								}
							]
						}
					]
				});

			const result = await checkS3ObjectLevelLogging();
			expect(result.checks).toHaveLength(2);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when S3 listing fails", async () => {
			mockS3Client.on(ListBucketsCommand).rejects(new Error("S3 API Error"));

			const result = await checkS3ObjectLevelLogging();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("S3 API Error");
		});

		it("should return ERROR when CloudTrail API fails", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockCloudTrailClient.on(ListTrailsCommand).rejects(new Error("CloudTrail API Error"));

			const result = await checkS3ObjectLevelLogging();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("CloudTrail API Error");
		});

		it("should handle GetEventSelectors API errors", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({
					Trails: [{ Name: mockTrailWithWriteLogging.Name }]
				})
				.on(GetTrailCommand)
				.resolves({ Trail: mockTrailWithWriteLogging })
				.on(GetEventSelectorsCommand)
				.rejects(new Error("GetEventSelectors Error"));

			const result = await checkS3ObjectLevelLogging();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});
});
