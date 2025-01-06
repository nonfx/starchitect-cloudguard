// @ts-nocheck
import {
	CloudFrontClient,
	ListDistributionsCommand,
	GetDistributionCommand
} from "@aws-sdk/client-cloudfront";
import { S3Client, ListBucketsCommand } from "@aws-sdk/client-s3";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkCloudFrontS3Origin from "./check-cloudfront-s3-origin";

const mockCloudFrontClient = mockClient(CloudFrontClient);
const mockS3Client = mockClient(S3Client);

const mockDistribution = {
	Id: "DIST123",
	ARN: "arn:aws:cloudfront::123456789012:distribution/DIST123",
	Status: "Deployed"
};

const mockS3Buckets = [{ Name: "existing-bucket", CreationDate: new Date() }];

describe("checkCloudFrontS3Origin", () => {
	beforeEach(() => {
		mockCloudFrontClient.reset();
		mockS3Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when CloudFront distribution points to existing S3 bucket", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockS3Buckets });
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistribution],
					Quantity: 1
				}
			});
			mockCloudFrontClient.on(GetDistributionCommand).resolves({
				Distribution: {
					DistributionConfig: {
						Origins: {
							Items: [
								{
									DomainName: "existing-bucket.s3.amazonaws.com",
									S3OriginConfig: {}
								}
							]
						}
					}
				}
			});

			const result = await checkCloudFrontS3Origin.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("DIST123");
		});

		it("should return PASS when distribution has no S3 origins", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockS3Buckets });
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistribution],
					Quantity: 1
				}
			});
			mockCloudFrontClient.on(GetDistributionCommand).resolves({
				Distribution: {
					DistributionConfig: {
						Origins: {
							Items: [
								{
									DomainName: "example.com",
									CustomOriginConfig: {}
								}
							]
						}
					}
				}
			});

			const result = await checkCloudFrontS3Origin.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when distribution points to non-existent S3 bucket", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockS3Buckets });
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistribution],
					Quantity: 1
				}
			});
			mockCloudFrontClient.on(GetDistributionCommand).resolves({
				Distribution: {
					DistributionConfig: {
						Origins: {
							Items: [
								{
									DomainName: "non-existent-bucket.s3.amazonaws.com",
									S3OriginConfig: {}
								}
							]
						}
					}
				}
			});

			const result = await checkCloudFrontS3Origin.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("non-existent S3 bucket");
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no distributions exist", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({
				Buckets: []
			});

			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [],
					Quantity: 0
				}
			});

			const result = await checkCloudFrontS3Origin.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No CloudFront distributions found");
		});

		it("should return ERROR when CloudFront API call fails", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).rejects(new Error("API Error"));

			const result = await checkCloudFrontS3Origin.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudFront distributions");
		});

		it("should return ERROR when GetDistribution fails for specific distribution", async () => {
			mockS3Client.on(ListBucketsCommand).resolves({ Buckets: mockS3Buckets });
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistribution],
					Quantity: 1
				}
			});
			mockCloudFrontClient.on(GetDistributionCommand).rejects(new Error("Access Denied"));

			const result = await checkCloudFrontS3Origin.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking distribution");
		});
	});
});
