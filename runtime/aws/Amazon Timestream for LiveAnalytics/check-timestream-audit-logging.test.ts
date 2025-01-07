// @ts-nocheck
import {
	CloudTrailClient,
	GetTrailCommand,
	ListTrailsCommand,
	GetEventSelectorsCommand
} from "@aws-sdk/client-cloudtrail";
import { TimestreamWriteClient, ListDatabasesCommand } from "@aws-sdk/client-timestream-write";
import { S3Client, GetBucketLoggingCommand, GetBucketEncryptionCommand } from "@aws-sdk/client-s3";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkTimestreamAuditLogging from "./check-timestream-audit-logging";

const mockCloudTrailClient = mockClient(CloudTrailClient);
const mockTimestreamClient = mockClient(TimestreamWriteClient);
const mockS3Client = mockClient(S3Client);

// Enhanced mock trails with more variations
const mockCompliantTrail = {
	Name: "compliant-trail",
	TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/compliant-trail",
	S3BucketName: "audit-logs-bucket",
	KmsKeyId: "arn:aws:kms:us-east-1:123456789012:key/mock-key",
	CloudWatchLogsLogGroupArn: "arn:aws:logs:us-east-1:123456789012:log-group:audit-logs",
	IsMultiRegionTrail: true
};

const mockCompliantEventSelectors = {
	EventSelectors: [
		{
			IncludeManagementEvents: true,
			DataResources: [
				{
					Type: "AWS::Timestream::Table",
					Values: ["*"]
				}
			]
		}
	]
};

const mockCompliantAdvancedEventSelectors = {
	AdvancedEventSelectors: [
		{
			Name: "Management Events",
			FieldSelectors: [
				{
					Field: "eventCategory",
					Equals: ["Management"]
				}
			]
		},
		{
			Name: "Timestream Events",
			FieldSelectors: [
				{
					Field: "eventSource",
					Equals: ["timestream.amazonaws.com"]
				},
				{
					Field: "resources.type",
					Equals: ["AWS::Timestream::Table"]
				}
			]
		}
	]
};

const mockPartiallyCompliantTrail = {
	Name: "partial-compliant-trail",
	TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/partial-trail",
	S3BucketName: "audit-logs-bucket",
	KmsKeyId: "arn:aws:kms:us-east-1:123456789012:key/mock-key",
	CloudWatchLogsLogGroupArn: "arn:aws:logs:us-east-1:123456789012:log-group:audit-logs",
	IsMultiRegionTrail: false
};

const mockNonCompliantTrail = {
	Name: "non-compliant-trail",
	TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/non-compliant-trail",
	S3BucketName: "audit-logs-bucket",
	IsMultiRegionTrail: false
};

describe("checkTimestreamAuditLogging", () => {
	beforeEach(() => {
		mockCloudTrailClient.reset();
		mockTimestreamClient.reset();
		mockS3Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when all requirements are met with standard event selectors", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: [{ DatabaseName: "test-db" }]
			});

			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({
					Trails: [{ Name: "compliant-trail", TrailARN: mockCompliantTrail.TrailARN }]
				})
				.on(GetTrailCommand)
				.resolves({ Trail: mockCompliantTrail })
				.on(GetEventSelectorsCommand)
				.resolves(mockCompliantEventSelectors);

			const result = await checkTimestreamAuditLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("compliant-trail");
			expect(result.checks[0].message).toBeUndefined();
		});

		it("should return PASS when all requirements are met with advanced event selectors", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: [{ DatabaseName: "test-db" }]
			});

			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({
					Trails: [{ Name: "compliant-trail", TrailARN: mockCompliantTrail.TrailARN }]
				})
				.on(GetTrailCommand)
				.resolves({ Trail: mockCompliantTrail })
				.on(GetEventSelectorsCommand)
				.resolves(mockCompliantAdvancedEventSelectors);

			const result = await checkTimestreamAuditLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("compliant-trail");
			expect(result.checks[0].message).toBeUndefined();
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when trail is not multi-region", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: [{ DatabaseName: "test-db" }]
			});

			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({
					Trails: [{ Name: "partial-trail", TrailARN: mockPartiallyCompliantTrail.TrailARN }]
				})
				.on(GetTrailCommand)
				.resolves({ Trail: mockPartiallyCompliantTrail })
				.on(GetEventSelectorsCommand)
				.resolves(mockCompliantEventSelectors);

			const result = await checkTimestreamAuditLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No compliant trail found. Trails must have management events or Timestream data events enabled, encryption, CloudWatch logs integration, and multi-region enabled"
			);
		});

		it("should return FAIL when trail is missing required components", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: [{ DatabaseName: "test-db" }]
			});

			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({
					Trails: [{ Name: "non-compliant-trail", TrailARN: mockNonCompliantTrail.TrailARN }]
				})
				.on(GetTrailCommand)
				.resolves({ Trail: mockNonCompliantTrail })
				.on(GetEventSelectorsCommand)
				.resolves({
					EventSelectors: [
						{
							IncludeManagementEvents: false,
							DataResources: []
						}
					]
				});

			const result = await checkTimestreamAuditLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No compliant trail found. Trails must have management events or Timestream data events enabled, encryption, CloudWatch logs integration, and multi-region enabled"
			);
		});

		it("should return NOTAPPLICABLE when no Timestream databases exist", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: []
			});

			const result = await checkTimestreamAuditLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Timestream databases found in the region");
		});

		it("should return FAIL when no CloudTrail trails exist", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: [{ DatabaseName: "test-db" }]
			});

			mockCloudTrailClient.on(ListTrailsCommand).resolves({ Trails: [] });

			const result = await checkTimestreamAuditLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No CloudTrail trails configured");
		});
	});

	describe("Error Handling", () => {
		it("should handle CloudTrail API errors", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: [{ DatabaseName: "test-db" }]
			});

			mockCloudTrailClient.on(ListTrailsCommand).rejects(new Error("CloudTrail API Error"));

			const result = await checkTimestreamAuditLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking audit logging: CloudTrail API Error");
		});

		it("should handle Timestream API errors", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).rejects(new Error("Timestream API Error"));

			const result = await checkTimestreamAuditLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking audit logging: Timestream API Error");
		});
	});
});
