import { CloudTrailClient, DescribeTrailsCommand } from "@aws-sdk/client-cloudtrail";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "@codegen/utils/stringUtils";
import checkCloudTrailLogValidation from "./check-cloudtrail-log-validation";

const mockCloudTrailClient = mockClient(CloudTrailClient);

const mockTrailWithValidation = {
	Name: "test-trail-1",
	TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail-1",
	LogFileValidationEnabled: true
};

const mockTrailWithoutValidation = {
	Name: "test-trail-2",
	TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail-2",
	LogFileValidationEnabled: false
};

describe("checkCloudTrailLogValidation", () => {
	beforeEach(() => {
		mockCloudTrailClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when log validation is enabled", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [mockTrailWithValidation]
			});

			const result = await checkCloudTrailLogValidation("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-trail-1");
			expect(result.checks[0].resourceArn).toBe(mockTrailWithValidation.TrailARN);
		});

		it("should handle multiple compliant trails", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [mockTrailWithValidation, mockTrailWithValidation]
			});

			const result = await checkCloudTrailLogValidation("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when log validation is disabled", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [mockTrailWithoutValidation]
			});

			const result = await checkCloudTrailLogValidation("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("CloudTrail log file validation is not enabled");
		});

		it("should handle mixed compliance states", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [mockTrailWithValidation, mockTrailWithoutValidation]
			});

			const result = await checkCloudTrailLogValidation("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle trails with missing name or ARN", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [{ LogFileValidationEnabled: true }]
			});

			const result = await checkCloudTrailLogValidation("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Trail found without name or ARN");
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no trails exist", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: []
			});

			const result = await checkCloudTrailLogValidation("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No CloudTrail trails found in the region");
		});

		it("should return ERROR when API call fails", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).rejects(new Error("API Error"));

			const result = await checkCloudTrailLogValidation("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking CloudTrail trails: API Error");
		});

		it("should handle undefined trailList", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({});

			const result = await checkCloudTrailLogValidation("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
