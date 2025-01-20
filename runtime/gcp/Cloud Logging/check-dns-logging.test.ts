// @ts-nocheck
import { v1 } from "@google-cloud/compute";
import { GoogleAuth } from "google-auth-library";
import { ComplianceStatus } from "../../types.js";
import checkDnsLogging from "./check-dns-logging.js";

describe("checkDnsLogging", () => {
	const mockListNetworks = jest.fn().mockResolvedValue([[]]);
	const mockRequest = jest.fn().mockResolvedValue({ data: { policies: [] } });
	const mockGetClient = jest.fn().mockResolvedValue({ request: mockRequest });

	beforeEach(() => {
		// Reset all mocks
		mockListNetworks.mockClear();
		mockRequest.mockClear();
		mockGetClient.mockClear();

		// Setup compute client mock
		v1.NetworksClient.prototype.list = mockListNetworks;

		// Setup auth mock
		GoogleAuth.prototype.getClient = mockGetClient;
	});

	describe("Compliant Resources", () => {
		it("should return PASS when DNS logging is enabled", async () => {
			const mockNetworks = [
				{
					name: "test-network",
					selfLink: "projects/test-project/global/networks/test-network"
				}
			];

			const mockPolicies = [
				{
					enableLogging: true,
					networks: [
						{
							networkUrl: "projects/test-project/global/networks/test-network"
						}
					]
				}
			];

			mockListNetworks.mockResolvedValueOnce([mockNetworks]);
			mockRequest.mockResolvedValueOnce({ data: { policies: mockPolicies } });

			const result = await checkDnsLogging.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-network");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when DNS logging is disabled", async () => {
			const mockNetworks = [
				{
					name: "test-network",
					selfLink: "projects/test-project/global/networks/test-network"
				}
			];

			const mockPolicies = [
				{
					enableLogging: false,
					networks: [
						{
							networkUrl: "projects/test-project/global/networks/test-network"
						}
					]
				}
			];

			mockListNetworks.mockResolvedValueOnce([mockNetworks]);
			mockRequest.mockResolvedValueOnce({ data: { policies: mockPolicies } });

			const result = await checkDnsLogging.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Cloud DNS logging is not enabled for this VPC network"
			);
		});

		it("should return FAIL when no DNS policy exists", async () => {
			const mockNetworks = [
				{
					name: "test-network",
					selfLink: "projects/test-project/global/networks/test-network"
				}
			];

			mockListNetworks.mockResolvedValueOnce([mockNetworks]);
			mockRequest.mockResolvedValueOnce({ data: { policies: [] } });

			const result = await checkDnsLogging.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Cloud DNS logging is not enabled for this VPC network"
			);
		});
	});

	describe("Not Applicable Cases", () => {
		it("should return NOTAPPLICABLE when no networks exist", async () => {
			mockListNetworks.mockResolvedValueOnce([[]]);

			const result = await checkDnsLogging.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No VPC networks found in the project");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when networks list fails", async () => {
			mockListNetworks.mockRejectedValueOnce(new Error("API Error"));

			const result = await checkDnsLogging.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking DNS logging");
		});

		it("should return ERROR when DNS policy request fails", async () => {
			const mockNetworks = [
				{
					name: "test-network",
					selfLink: "projects/test-project/global/networks/test-network"
				}
			];

			mockListNetworks.mockResolvedValueOnce([mockNetworks]);
			mockRequest.mockRejectedValueOnce(new Error("API Error"));

			const result = await checkDnsLogging.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking DNS logging");
		});

		it("should handle network without name", async () => {
			const mockNetworks = [
				{
					selfLink: "projects/test-project/global/networks/test-network"
				}
			];

			mockListNetworks.mockResolvedValueOnce([mockNetworks]);

			const result = await checkDnsLogging.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Network found without name");
		});
	});
});
