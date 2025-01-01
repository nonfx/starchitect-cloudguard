// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import {
	CloudTrailClient,
	GetTrailCommand,
	ListTrailsCommand,
	GetEventSelectorsCommand
} from "@aws-sdk/client-cloudtrail";
import { S3Client, ListBucketsCommand } from "@aws-sdk/client-s3";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkS3ObjectReadLogging from "./check-s3-object-read-logging";

const mockCloudTrailClient = mockClient(CloudTrailClient);
const mockS3Client = mockClient(S3Client);

const mockBuckets = [
	{ Name: "test-bucket-1", CreationDate: new Date() },
	{ Name: "test-bucket-2", CreationDate: new Date() }
];

const mockTrails = [
	{ Name: "trail-1", TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/trail-1" },
	{ Name: "trail-2", TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/trail-2" }
];

describe("checkS3ObjectReadLogging", () => {
	beforeEach(() => {
		mockCloudTrailClient.reset();
		mockS3Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when buckets have read logging enabled globally", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({ Trails: mockTrails })
				.on(GetTrailCommand)
				.resolves({ Trail: mockTrails[0] })
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

			const result = await checkS3ObjectReadLogging.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});

		it("should return PASS when buckets have specific bucket logging enabled", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({ Trails: mockTrails })
				.on(GetTrailCommand)
				.resolves({ Trail: mockTrails[0] })
				.on(GetEventSelectorsCommand)
				.resolves({
					EventSelectors: [
						{
							ReadWriteType: "ReadOnly",
							DataResources: [
								{
									Type: "AWS::S3::Object",
									Values: ["arn:aws:s3:::test-bucket-1/*"]
								}
							]
						}
					]
				});

			const result = await checkS3ObjectReadLogging.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});

		it("should return PASS with advanced event selectors", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({ Trails: mockTrails })
				.on(GetTrailCommand)
				.resolves({ Trail: mockTrails[0] })
				.on(GetEventSelectorsCommand)
				.resolves({
					AdvancedEventSelectors: [
						{
							FieldSelectors: [
								{ Field: "readOnly", Equals: ["true"] },
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

			const result = await checkS3ObjectReadLogging.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no CloudTrail trails exist", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockCloudTrailClient.on(ListTrailsCommand).resolves({ Trails: [] });

			const result = await checkS3ObjectReadLogging.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("No CloudTrail trails configured");
		});

		it("should return FAIL when trails do not monitor S3 object-level operations", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({ Trails: mockTrails })
				.on(GetTrailCommand)
				.resolves({ Trail: mockTrails[0] })
				.on(GetEventSelectorsCommand)
				.resolves({
					EventSelectors: [
						{
							ReadWriteType: "WriteOnly",
							DataResources: [
								{
									Type: "AWS::S3::Object",
									Values: ["arn:aws:s3"]
								}
							]
						}
					]
				});

			const result = await checkS3ObjectReadLogging.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain(
				"does not have object-level read event logging enabled"
			);
		});

		it("should return FAIL with incomplete advanced event selectors", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [mockBuckets[0]] });
			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({ Trails: mockTrails })
				.on(GetTrailCommand)
				.resolves({ Trail: mockTrails[0] })
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

			const result = await checkS3ObjectReadLogging.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no S3 buckets exist", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: [] });

			const result = await checkS3ObjectReadLogging.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});

		it("should return ERROR when API calls fail", async () => {
			mockS3Client.on(ListBucketsCommand).rejects(new Error("API Error"));

			const result = await checkS3ObjectReadLogging.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking S3 and CloudTrail configuration");
		});

		it("should handle trails with missing event selectors", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({ Trails: mockTrails })
				.on(GetTrailCommand)
				.resolves({ Trail: mockTrails[0] })
				.on(GetEventSelectorsCommand)
				.resolves({});

			const result = await checkS3ObjectReadLogging.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle GetEventSelectors API errors", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockBuckets });
			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({ Trails: mockTrails })
				.on(GetTrailCommand)
				.resolves({ Trail: mockTrails[0] })
				.on(GetEventSelectorsCommand)
				.rejects(new Error("GetEventSelectors Error"));

			const result = await checkS3ObjectReadLogging.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});
});
