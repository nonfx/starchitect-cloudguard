import {
	CloudTrailClient,
	DescribeTrailsCommand,
	GetTrailStatusCommand
} from "@aws-sdk/client-cloudtrail";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "@codegen/utils/stringUtils";
import checkCloudTrailEnabled from "./check-cloudtrail-enabled";

const mockCloudTrailClient = mockClient(CloudTrailClient);

const mockEnabledMultiRegionTrail = {
	Name: "enabled-multi-region-trail",
	TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/enabled-multi-region-trail",
	IsMultiRegionTrail: true
};

const mockDisabledTrail = {
	Name: "disabled-trail",
	TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/disabled-trail",
	IsMultiRegionTrail: true
};

const mockSingleRegionTrail = {
	Name: "single-region-trail",
	TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/single-region-trail",
	IsMultiRegionTrail: false
};

describe("checkCloudTrailEnabled", () => {
	beforeEach(() => {
		mockCloudTrailClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when multi-region trail is enabled", async () => {
			mockCloudTrailClient
				.on(DescribeTrailsCommand)
				.resolves({
					trailList: [mockEnabledMultiRegionTrail]
				})
				.on(GetTrailStatusCommand)
				.resolves({
					IsLogging: true
				});

			const result = await checkCloudTrailEnabled();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("enabled-multi-region-trail");
			expect(result.checks[0].resourceArn).toBe(mockEnabledMultiRegionTrail.TrailARN);
		});

		it("should return PASS for enabled multi-region trail among multiple trails", async () => {
			mockCloudTrailClient
				.on(DescribeTrailsCommand)
				.resolves({
					trailList: [mockDisabledTrail, mockEnabledMultiRegionTrail, mockSingleRegionTrail]
				})
				.on(GetTrailStatusCommand)
				.callsFake(input => {
					switch (input.Name) {
						case mockEnabledMultiRegionTrail.Name:
							return Promise.resolve({ IsLogging: true });
						case mockDisabledTrail.Name:
							return Promise.resolve({ IsLogging: false });
						case mockSingleRegionTrail.Name:
							return Promise.resolve({ IsLogging: true });
						default:
							return Promise.reject(new Error("Unknown trail"));
					}
				});

			const result = await checkCloudTrailEnabled();
			expect(result.checks.some(check => check.status === ComplianceStatus.PASS)).toBeTruthy();
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no trails exist", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: []
			});

			const result = await checkCloudTrailEnabled();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No CloudTrail trails found in the account");
		});

		it("should return FAIL for disabled trails", async () => {
			mockCloudTrailClient
				.on(DescribeTrailsCommand)
				.resolves({
					trailList: [mockDisabledTrail]
				})
				.on(GetTrailStatusCommand)
				.resolves({
					IsLogging: false
				});

			const result = await checkCloudTrailEnabled();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Trail logging is not enabled");
		});

		it("should return FAIL for single-region trails", async () => {
			mockCloudTrailClient
				.on(DescribeTrailsCommand)
				.resolves({
					trailList: [mockSingleRegionTrail]
				})
				.on(GetTrailStatusCommand)
				.resolves({
					IsLogging: true
				});

			const result = await checkCloudTrailEnabled();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Trail is not multi-region");
		});

		it("should handle trails without name or ARN", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
				trailList: [{ IsMultiRegionTrail: true }]
			});

			const result = await checkCloudTrailEnabled();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Trail found without name or ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when DescribeTrails API call fails", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).rejects(new Error("API Error"));

			const result = await checkCloudTrailEnabled();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking CloudTrail trails: API Error");
		});

		it("should return ERROR when GetTrailStatus API call fails", async () => {
			mockCloudTrailClient
				.on(DescribeTrailsCommand)
				.resolves({
					trailList: [mockEnabledMultiRegionTrail]
				})
				.on(GetTrailStatusCommand)
				.rejects(new Error("Status API Error"));

			const result = await checkCloudTrailEnabled();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking CloudTrail trails: Status API Error");
		});

		it("should handle undefined trailList", async () => {
			mockCloudTrailClient.on(DescribeTrailsCommand).resolves({});

			const result = await checkCloudTrailEnabled();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No CloudTrail trails found in the account");
		});
	});
});
