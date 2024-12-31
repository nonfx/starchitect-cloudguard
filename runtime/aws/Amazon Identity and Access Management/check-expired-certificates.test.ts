// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { IAMClient, ListServerCertificatesCommand } from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkExpiredCertificates from "./check-expired-certificates";

const mockIAMClient = mockClient(IAMClient);

const futureDate = new Date();
futureDate.setFullYear(futureDate.getFullYear() + 1);

const pastDate = new Date();
pastDate.setFullYear(pastDate.getFullYear() - 1);

const mockValidCertificate = {
	ServerCertificateName: "valid-cert",
	Arn: "arn:aws:iam::123456789012:server-certificate/valid-cert",
	Expiration: futureDate
};

const mockExpiredCertificate = {
	ServerCertificateName: "expired-cert",
	Arn: "arn:aws:iam::123456789012:server-certificate/expired-cert",
	Expiration: pastDate
};

describe("checkExpiredCertificates", () => {
	beforeEach(() => {
		mockIAMClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for valid certificates", async () => {
			mockIAMClient.on(ListServerCertificatesCommand).resolves({
				ServerCertificateMetadataList: [mockValidCertificate]
			});

			const result = await checkExpiredCertificates.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("valid-cert");
			expect(result.checks[0].resourceArn).toBe(mockValidCertificate.Arn);
		});

		it("should return NOTAPPLICABLE when no certificates exist", async () => {
			mockIAMClient.on(ListServerCertificatesCommand).resolves({
				ServerCertificateMetadataList: []
			});

			const result = await checkExpiredCertificates.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No SSL/TLS certificates found in IAM storage");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for expired certificates", async () => {
			mockIAMClient.on(ListServerCertificatesCommand).resolves({
				ServerCertificateMetadataList: [mockExpiredCertificate]
			});

			const result = await checkExpiredCertificates.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("Certificate expired on");
		});

		it("should handle mixed valid and expired certificates", async () => {
			mockIAMClient.on(ListServerCertificatesCommand).resolves({
				ServerCertificateMetadataList: [mockValidCertificate, mockExpiredCertificate]
			});

			const result = await checkExpiredCertificates.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle certificates without name or ARN", async () => {
			mockIAMClient.on(ListServerCertificatesCommand).resolves({
				ServerCertificateMetadataList: [{ Expiration: futureDate }]
			});

			const result = await checkExpiredCertificates.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Certificate found without name or ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockIAMClient.on(ListServerCertificatesCommand).rejects(new Error("API Error"));

			const result = await checkExpiredCertificates.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking SSL/TLS certificates");
		});

		it("should handle undefined ServerCertificateMetadataList", async () => {
			mockIAMClient.on(ListServerCertificatesCommand).resolves({});

			const result = await checkExpiredCertificates.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
