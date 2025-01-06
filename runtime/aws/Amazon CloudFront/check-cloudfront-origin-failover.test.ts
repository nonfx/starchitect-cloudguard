// @ts-nocheck
import {
	CloudFrontClient,
	ListDistributionsCommand,
	GetDistributionCommand
} from "@aws-sdk/client-cloudfront";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkCloudFrontOriginFailover from "./check-cloudfront-origin-failover";

const mockCloudFrontClient = mockClient(CloudFrontClient);

const mockDistributionWithFailover = {
	Id: "DIST123",
	ARN: "arn:aws:cloudfront::123456789012:distribution/DIST123",
	DistributionConfig: {
		OriginGroups: {
			Items: [
				{
					Members: {
						Items: [{ OriginId: "primary" }, { OriginId: "secondary" }]
					}
				}
			]
		}
	}
};

const mockDistributionWithoutFailover = {
	Id: "DIST456",
	ARN: "arn:aws:cloudfront::123456789012:distribution/DIST456",
	DistributionConfig: {
		OriginGroups: {
			Items: []
		}
	}
};

describe("checkCloudFrontOriginFailover", () => {
	beforeEach(() => {
		mockCloudFrontClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when distribution has origin failover configured", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [{ Id: "DIST123", ARN: mockDistributionWithFailover.ARN }]
				}
			});

			mockCloudFrontClient
				.on(GetDistributionCommand)
				.resolves({ Distribution: mockDistributionWithFailover });

			const result = await checkCloudFrontOriginFailover.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceArn).toBe(mockDistributionWithFailover.ARN);
		});

		it("should return NOTAPPLICABLE when no distributions exist", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: { Items: [] }
			});

			const result = await checkCloudFrontOriginFailover.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No CloudFront distributions found");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when distribution has no origin failover", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [{ Id: "DIST456", ARN: mockDistributionWithoutFailover.ARN }]
				}
			});

			mockCloudFrontClient
				.on(GetDistributionCommand)
				.resolves({ Distribution: mockDistributionWithoutFailover });

			const result = await checkCloudFrontOriginFailover.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Distribution does not have origin failover configured with at least two origins"
			);
		});

		it("should handle multiple distributions with mixed configurations", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [
						{ Id: "DIST123", ARN: mockDistributionWithFailover.ARN },
						{ Id: "DIST456", ARN: mockDistributionWithoutFailover.ARN }
					]
				}
			});

			mockCloudFrontClient
				.on(GetDistributionCommand, { Id: "DIST123" })
				.resolves({ Distribution: mockDistributionWithFailover });

			mockCloudFrontClient
				.on(GetDistributionCommand, { Id: "DIST456" })
				.resolves({ Distribution: mockDistributionWithoutFailover });

			const result = await checkCloudFrontOriginFailover.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListDistributions fails", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).rejects(new Error("API Error"));

			const result = await checkCloudFrontOriginFailover.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudFront distributions");
		});

		it("should return ERROR when GetDistribution fails", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [{ Id: "DIST123" }]
				}
			});

			mockCloudFrontClient.on(GetDistributionCommand).rejects(new Error("Access Denied"));

			const result = await checkCloudFrontOriginFailover.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking distribution");
		});

		it("should handle distribution without ID", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [{}]
				}
			});

			const result = await checkCloudFrontOriginFailover.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Distribution found without ID");
		});
	});
});
