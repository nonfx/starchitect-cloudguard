// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { CloudTrailClient, DescribeTrailsCommand } from "@aws-sdk/client-cloudtrail";
import { S3Client, GetBucketPolicyCommand, GetBucketAclCommand } from "@aws-sdk/client-s3";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkCloudTrailBucketAccess from "./check-cloudtrail-bucket-access";

const mockCloudTrailClient = mockClient(CloudTrailClient);
const mockS3Client = mockClient(S3Client);

const mockTrail = {
	Name: "test-trail",
	TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail",
	S3BucketName: "test-bucket"
};

describe("checkCloudTrailBucketAccess", () => {
	beforeEach(() => {
		mockCloudTrailClient.reset();
		mockS3Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when S3 bucket is not publicly accessible", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [mockTrail]
			});

			// Private bucket policy
			mockS3Client.on(GetBucketPolicyCommand).resolves({
				Policy: JSON.stringify({
					Statement: [
						{
							Effect: "Allow",
							Principal: { AWS: "arn:aws:iam::123456789012:root" },
							Action: "s3:*",
							Resource: "arn:aws:s3:::test-bucket/*"
						}
					]
				})
			});

			// Private bucket ACL
			mockS3Client.on(GetBucketAclCommand).resolves({
				Grants: [
					{
						Grantee: {
							Type: "CanonicalUser",
							ID: "ownerid"
						}
					}
				]
			});

			const result = await checkCloudTrailBucketAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-bucket");
		});

		it("should handle missing bucket policy gracefully", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [mockTrail]
			});

			mockS3Client.on(GetBucketPolicyCommand).rejects({
				name: "NoSuchBucketPolicy"
			});

			mockS3Client.on(GetBucketAclCommand).resolves({
				Grants: [
					{
						Grantee: {
							Type: "CanonicalUser",
							ID: "ownerid"
						}
					}
				]
			});

			const result = await checkCloudTrailBucketAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when bucket has public policy", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [mockTrail]
			});

			mockS3Client.on(GetBucketPolicyCommand).resolves({
				Policy: JSON.stringify({
					Statement: [
						{
							Effect: "Allow",
							Principal: "*",
							Action: "s3:GetObject",
							Resource: "arn:aws:s3:::test-bucket/*"
						}
					]
				})
			});

			const result = await checkCloudTrailBucketAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("CloudTrail S3 bucket is publicly accessible");
		});

		it("should return FAIL when bucket has public ACL", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [mockTrail]
			});

			mockS3Client.on(GetBucketPolicyCommand).rejects({
				name: "NoSuchBucketPolicy"
			});

			mockS3Client.on(GetBucketAclCommand).resolves({
				Grants: [
					{
						Grantee: {
							Type: "Group",
							URI: "http://acs.amazonaws.com/groups/global/AllUsers"
						}
					}
				]
			});

			const result = await checkCloudTrailBucketAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no trails exist", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: []
			});

			const result = await checkCloudTrailBucketAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No CloudTrail trails found");
		});

		it("should return ERROR when CloudTrail API fails", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).rejects(new Error("CloudTrail API error"));

			const result = await checkCloudTrailBucketAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudTrail");
		});

		it("should return ERROR when S3 API fails", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [mockTrail]
			});

			mockS3Client.on(GetBucketPolicyCommand).rejects(new Error("S3 API error"));

			const result = await checkCloudTrailBucketAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking bucket");
		});

		it("should handle trails without S3 bucket", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [
					{
						Name: "invalid-trail",
						TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/invalid-trail"
					}
				]
			});

			const result = await checkCloudTrailBucketAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Trail has no S3 bucket configured");
		});
	});
});
