// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { CloudTrailClient, DescribeTrailsCommand } from "@aws-sdk/client-cloudtrail";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkCloudTrailKmsEncryption from "./check-cloudtrail-kms-encryption";

const mockCloudTrailClient = mockClient(CloudTrailClient);

const mockTrailWithKMS = {
	Name: "trail-with-kms",
	TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/trail-with-kms",
	KmsKeyId: "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
};

const mockTrailWithoutKMS = {
	Name: "trail-without-kms",
	TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/trail-without-kms"
};

describe("checkCloudTrailKmsEncryption", () => {
	beforeEach(() => {
		mockCloudTrailClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when CloudTrail uses KMS encryption", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [mockTrailWithKMS]
			});

			const result = await checkCloudTrailKmsEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("trail-with-kms");
			expect(result.checks[0].resourceArn).toBe(mockTrailWithKMS.TrailARN);
		});

		it("should handle multiple compliant trails", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [mockTrailWithKMS, { ...mockTrailWithKMS, Name: "trail-2", TrailARN: "arn:2" }]
			});

			const result = await checkCloudTrailKmsEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when CloudTrail does not use KMS encryption", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [mockTrailWithoutKMS]
			});

			const result = await checkCloudTrailKmsEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"CloudTrail is not configured to use SSE-KMS encryption"
			);
		});

		it("should handle mixed compliance scenarios", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [mockTrailWithKMS, mockTrailWithoutKMS]
			});

			const result = await checkCloudTrailKmsEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle trails without names", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [{ TrailARN: "arn:unnamed" }]
			});

			const result = await checkCloudTrailKmsEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Trail found without name");
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no trails exist", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: []
			});

			const result = await checkCloudTrailKmsEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No CloudTrail trails found in the region");
		});

		it("should return ERROR when API call fails", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).rejects(new Error("API Error"));

			const result = await checkCloudTrailKmsEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudTrail trails");
		});

		it("should handle undefined trailList", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({});

			const result = await checkCloudTrailKmsEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
