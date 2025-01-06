// @ts-nocheck
import { CloudFrontClient, ListDistributionsCommand } from "@aws-sdk/client-cloudfront";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkCloudFrontSni from "./check-cloudfront-sni";

const mockCloudFrontClient = mockClient(CloudFrontClient);

const mockDistributionWithSNI = {
	Id: "DIST1",
	ARN: "arn:aws:cloudfront::123456789012:distribution/DIST1",
	ViewerCertificate: {
		SSLSupportMethod: "sni-only",
		CloudFrontDefaultCertificate: false
	}
};

const mockDistributionWithoutSNI = {
	Id: "DIST2",
	ARN: "arn:aws:cloudfront::123456789012:distribution/DIST2",
	ViewerCertificate: {
		SSLSupportMethod: "vip",
		CloudFrontDefaultCertificate: false
	}
};

const mockDistributionWithDefaultCert = {
	Id: "DIST3",
	ARN: "arn:aws:cloudfront::123456789012:distribution/DIST3",
	ViewerCertificate: {
		CloudFrontDefaultCertificate: true
	}
};

describe("checkCloudFrontSni", () => {
	beforeEach(() => {
		mockCloudFrontClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when distribution uses SNI", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistributionWithSNI]
				}
			});

			const result = await checkCloudFrontSni.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("DIST1");
		});

		it("should return PASS when using CloudFront default certificate", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistributionWithDefaultCert]
				}
			});

			const result = await checkCloudFrontSni.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toBe("Using CloudFront default certificate");
		});

		it("should return NOTAPPLICABLE when no distributions exist", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: []
				}
			});

			const result = await checkCloudFrontSni.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No CloudFront distributions found");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when distribution does not use SNI", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistributionWithoutSNI]
				}
			});

			const result = await checkCloudFrontSni.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Distribution is not configured to use SNI for HTTPS requests"
			);
		});

		it("should handle mixed compliance scenarios", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [
						mockDistributionWithSNI,
						mockDistributionWithoutSNI,
						mockDistributionWithDefaultCert
					]
				}
			});

			const result = await checkCloudFrontSni.execute();
			expect(result.checks).toHaveLength(3);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[2].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).rejects(new Error("API Error"));

			const result = await checkCloudFrontSni.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudFront distributions");
		});

		it("should handle distributions without ID or ARN", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [{ ViewerCertificate: { SSLSupportMethod: "sni-only" } }]
				}
			});

			const result = await checkCloudFrontSni.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Distribution found without ID or ARN");
		});
	});
});
