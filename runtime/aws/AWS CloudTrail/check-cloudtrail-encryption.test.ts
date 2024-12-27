// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { CloudTrailClient, DescribeTrailsCommand } from "@aws-sdk/client-cloudtrail";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types";
import checkCloudTrailEncryption from "./check-cloudtrail-encryption";

const mockCloudTrailClient = mockClient(CloudTrailClient);

const mockEncryptedTrail = {
	Name: "encrypted-trail",
	TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/encrypted-trail",
	KmsKeyId: "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
};

const mockUnencryptedTrail = {
	Name: "unencrypted-trail",
	TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/unencrypted-trail",
	KmsKeyId: ""
};

describe("checkCloudTrailEncryption", () => {
	beforeEach(() => {
		mockCloudTrailClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when trail is encrypted with KMS", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [mockEncryptedTrail]
			});

			const result = await checkCloudTrailEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("encrypted-trail");
			expect(result.checks[0].resourceArn).toBe(mockEncryptedTrail.TrailARN);
		});

		it("should handle multiple encrypted trails", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [mockEncryptedTrail, { ...mockEncryptedTrail, Name: "encrypted-trail-2" }]
			});

			const result = await checkCloudTrailEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when trail is not encrypted", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [mockUnencryptedTrail]
			});

			const result = await checkCloudTrailEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("CloudTrail trail is not encrypted with KMS key");
		});

		it("should handle mixed encrypted and unencrypted trails", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [mockEncryptedTrail, mockUnencryptedTrail]
			});

			const result = await checkCloudTrailEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle trails with missing name or ARN", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [{ KmsKeyId: "some-key" }]
			});

			const result = await checkCloudTrailEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Trail found without name or ARN");
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no trails exist", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: []
			});

			const result = await checkCloudTrailEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No CloudTrail trails found in the account");
		});

		it("should return ERROR when API call fails", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).rejects(new Error("API Error"));

			const result = await checkCloudTrailEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking CloudTrail trails: API Error");
		});

		it("should handle undefined trailList in response", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({});

			const result = await checkCloudTrailEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
