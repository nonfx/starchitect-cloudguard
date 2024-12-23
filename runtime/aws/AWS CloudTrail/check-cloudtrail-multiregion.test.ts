import {
	CloudTrailClient,
	GetTrailCommand,
	ListTrailsCommand,
	GetTrailStatusCommand
} from "@aws-sdk/client-cloudtrail";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "@codegen/utils/stringUtils";
import checkCloudTrailMultiRegionEnabled from "./check-cloudtrail-multiregion";

const mockCloudTrailClient = mockClient(CloudTrailClient);

const mockCompliantTrail = {
	Name: "compliant-trail",
	TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/compliant-trail",
	IsMultiRegionTrail: true,
	IncludeGlobalServiceEvents: true
};

const mockNonCompliantTrail = {
	Name: "non-compliant-trail",
	TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/non-compliant-trail",
	IsMultiRegionTrail: false,
	IncludeGlobalServiceEvents: false
};

describe("checkCloudTrailMultiRegionEnabled", () => {
	beforeEach(() => {
		mockCloudTrailClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when a compliant multi-region trail exists", async () => {
			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({
					Trails: [{ Name: mockCompliantTrail.Name, TrailARN: mockCompliantTrail.TrailARN }]
				})
				.on(GetTrailCommand)
				.resolves({ Trail: mockCompliantTrail })
				.on(GetTrailStatusCommand)
				.resolves({ IsLogging: true });

			const result = await checkCloudTrailMultiRegionEnabled("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe(mockCompliantTrail.Name);
		});

		it("should handle multiple trails with at least one compliant", async () => {
			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({
					Trails: [
						{ Name: mockCompliantTrail.Name, TrailARN: mockCompliantTrail.TrailARN },
						{ Name: mockNonCompliantTrail.Name, TrailARN: mockNonCompliantTrail.TrailARN }
					]
				})
				.on(GetTrailCommand)
				.callsFake(input => {
					const trail =
						input.Name === mockCompliantTrail.Name ? mockCompliantTrail : mockNonCompliantTrail;
					return Promise.resolve({ Trail: trail });
				})
				.on(GetTrailStatusCommand)
				.callsFake(input => {
					return Promise.resolve({
						IsLogging: input.Name === mockCompliantTrail.Name
					});
				});

			const result = await checkCloudTrailMultiRegionEnabled("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.some(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no trails exist", async () => {
			mockCloudTrailClient.on(ListTrailsCommand).resolves({ Trails: [] });

			const result = await checkCloudTrailMultiRegionEnabled("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No CloudTrail trails are configured");
		});

		it("should return FAIL when trail is not multi-region", async () => {
			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({
					Trails: [{ Name: mockNonCompliantTrail.Name, TrailARN: mockNonCompliantTrail.TrailARN }]
				})
				.on(GetTrailCommand)
				.resolves({ Trail: mockNonCompliantTrail })
				.on(GetTrailStatusCommand)
				.resolves({ IsLogging: true });

			const result = await checkCloudTrailMultiRegionEnabled("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("not multi-region");
		});

		it("should return FAIL when no compliant trails exist among multiple trails", async () => {
			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({
					Trails: [
						{ Name: mockNonCompliantTrail.Name, TrailARN: mockNonCompliantTrail.TrailARN },
						{ Name: "non-logging-trail", TrailARN: "arn:aws:cloudtrail:trail2" }
					]
				})
				.on(GetTrailCommand)
				.callsFake(input => {
					const trail = {
						...mockNonCompliantTrail,
						Name: input.Name,
						TrailARN:
							input.Name === "non-logging-trail"
								? "arn:aws:cloudtrail:trail2"
								: mockNonCompliantTrail.TrailARN
					};
					return Promise.resolve({ Trail: trail });
				})
				.on(GetTrailStatusCommand)
				.callsFake(input => {
					return Promise.resolve({
						IsLogging: input.Name === mockNonCompliantTrail.Name
					});
				});

			const result = await checkCloudTrailMultiRegionEnabled("us-east-1");
			expect(result.checks).toHaveLength(3); // Including summary check
			expect(result.checks[2].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[2].message).toContain("No compliant multi-region trail");
		});
	});

	describe("Error Handling", () => {
		it("should handle ListTrails API errors", async () => {
			mockCloudTrailClient.on(ListTrailsCommand).rejects(new Error("API Error"));

			const result = await checkCloudTrailMultiRegionEnabled("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudTrail configuration");
		});

		it("should handle GetTrail API errors", async () => {
			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({
					Trails: [{ Name: mockCompliantTrail.Name, TrailARN: mockCompliantTrail.TrailARN }]
				})
				.on(GetTrailCommand)
				.rejects(new Error("Access Denied"));

			const result = await checkCloudTrailMultiRegionEnabled("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking trail configuration");
		});

		it("should handle GetTrailStatus API errors", async () => {
			mockCloudTrailClient
				.on(ListTrailsCommand)
				.resolves({
					Trails: [{ Name: mockCompliantTrail.Name, TrailARN: mockCompliantTrail.TrailARN }]
				})
				.on(GetTrailCommand)
				.resolves({ Trail: mockCompliantTrail })
				.on(GetTrailStatusCommand)
				.rejects(new Error("Status API Error"));

			const result = await checkCloudTrailMultiRegionEnabled("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking trail configuration");
		});

		it("should handle trails without name or ARN", async () => {
			mockCloudTrailClient.on(ListTrailsCommand).resolves({
				Trails: [{}]
			});

			const result = await checkCloudTrailMultiRegionEnabled("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Trail found without name or ARN");
		});
	});
});
