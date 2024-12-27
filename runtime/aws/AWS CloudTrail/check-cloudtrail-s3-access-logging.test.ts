// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { S3Client, GetBucketLoggingCommand } from "@aws-sdk/client-s3";
import { CloudTrailClient, ListTrailsCommand, GetTrailCommand } from "@aws-sdk/client-cloudtrail";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types";
import checkCloudTrailS3AccessLogging from "./check-cloudtrail-s3-access-logging";

const mockS3Client = mockClient(S3Client);
const mockCloudTrailClient = mockClient(CloudTrailClient);

const mockTrail = {
	Name: "test-trail",
	TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail",
	S3BucketName: "test-bucket"
};

describe("checkCloudTrailS3AccessLogging", () => {
	beforeEach(() => {
		mockS3Client.reset();
		mockCloudTrailClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when S3 bucket has access logging enabled", async () => {
			mockCloudTrailClient.on(ListTrailsCommand).resolves({
				Trails: [{ Name: mockTrail.Name, TrailARN: mockTrail.TrailARN }]
			});
			mockCloudTrailClient.on(GetTrailCommand).resolves({
				Trail: mockTrail
			});
			mockS3Client.on(GetBucketLoggingCommand).resolves({
				LoggingEnabled: {
					TargetBucket: "logging-bucket",
					TargetPrefix: "logs/"
				}
			});

			const result = await checkCloudTrailS3AccessLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe(mockTrail.S3BucketName);
		});

		it("should handle multiple compliant trails", async () => {
			const trails = [
				{ Name: "trail-1", TrailARN: "arn:aws:cloudtrail:trail-1" },
				{ Name: "trail-2", TrailARN: "arn:aws:cloudtrail:trail-2" }
			];

			mockCloudTrailClient.on(ListTrailsCommand).resolves({ Trails: trails });
			mockCloudTrailClient.on(GetTrailCommand).resolves({
				Trail: { ...mockTrail, S3BucketName: "test-bucket" }
			});
			mockS3Client.on(GetBucketLoggingCommand).resolves({
				LoggingEnabled: { TargetBucket: "logging-bucket" }
			});

			const result = await checkCloudTrailS3AccessLogging.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when S3 bucket logging is not enabled", async () => {
			mockCloudTrailClient.on(ListTrailsCommand).resolves({
				Trails: [{ Name: mockTrail.Name, TrailARN: mockTrail.TrailARN }]
			});
			mockCloudTrailClient.on(GetTrailCommand).resolves({
				Trail: mockTrail
			});
			mockS3Client.on(GetBucketLoggingCommand).resolves({});

			const result = await checkCloudTrailS3AccessLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"CloudTrail S3 bucket does not have access logging enabled"
			);
		});

		it("should handle trails without S3 bucket configuration", async () => {
			mockCloudTrailClient.on(ListTrailsCommand).resolves({
				Trails: [{ Name: mockTrail.Name, TrailARN: mockTrail.TrailARN }]
			});
			mockCloudTrailClient.on(GetTrailCommand).resolves({
				Trail: { Name: mockTrail.Name }
			});

			const result = await checkCloudTrailS3AccessLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Trail has no S3 bucket configured");
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no trails exist", async () => {
			mockCloudTrailClient.on(ListTrailsCommand).resolves({ Trails: [] });

			const result = await checkCloudTrailS3AccessLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No CloudTrail trails found in the region");
		});

		it("should handle ListTrails API errors", async () => {
			mockCloudTrailClient.on(ListTrailsCommand).rejects(new Error("API Error"));

			const result = await checkCloudTrailS3AccessLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudTrail trails");
		});

		it("should handle GetBucketLogging API errors", async () => {
			mockCloudTrailClient.on(ListTrailsCommand).resolves({
				Trails: [{ Name: mockTrail.Name, TrailARN: mockTrail.TrailARN }]
			});
			mockCloudTrailClient.on(GetTrailCommand).resolves({
				Trail: mockTrail
			});
			mockS3Client.on(GetBucketLoggingCommand).rejects(new Error("Access Denied"));

			const result = await checkCloudTrailS3AccessLogging.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking bucket logging");
		});
	});
});
