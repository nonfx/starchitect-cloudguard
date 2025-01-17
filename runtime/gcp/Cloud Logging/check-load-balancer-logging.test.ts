// @ts-nocheck
import { v1 } from "@google-cloud/compute";
import { ComplianceStatus } from "../../types.js";
import checkLoadBalancerLogging from "./check-load-balancer-logging.js";

describe("checkLoadBalancerLogging", () => {
	const mockListBackendServices = jest.fn().mockResolvedValue([[]]);

	beforeEach(() => {
		// Reset all mocks
		mockListBackendServices.mockClear();

		// Setup compute client mock
		v1.BackendServicesClient.prototype.list = mockListBackendServices;
	});

	describe("Compliant Resources", () => {
		it("should return PASS when logging is properly configured", async () => {
			const mockServices = [
				{
					name: "test-backend",
					selfLink: "projects/test-project/global/backendServices/test-backend",
					logConfig: {
						enable: true,
						sampleRate: 1.0
					}
				}
			];

			mockListBackendServices.mockResolvedValueOnce([mockServices]);

			const result = await checkLoadBalancerLogging.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-backend");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when logging is disabled", async () => {
			const mockServices = [
				{
					name: "test-backend",
					selfLink: "projects/test-project/global/backendServices/test-backend",
					logConfig: {
						enable: false,
						sampleRate: 1.0
					}
				}
			];

			mockListBackendServices.mockResolvedValueOnce([mockServices]);

			const result = await checkLoadBalancerLogging.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Backend service logging is not enabled");
		});

		it("should return FAIL when sample rate is 0", async () => {
			const mockServices = [
				{
					name: "test-backend",
					selfLink: "projects/test-project/global/backendServices/test-backend",
					logConfig: {
						enable: true,
						sampleRate: 0
					}
				}
			];

			mockListBackendServices.mockResolvedValueOnce([mockServices]);

			const result = await checkLoadBalancerLogging.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Backend service logging sample rate must be greater than 0"
			);
		});

		it("should return FAIL when log config is missing", async () => {
			const mockServices = [
				{
					name: "test-backend",
					selfLink: "projects/test-project/global/backendServices/test-backend"
				}
			];

			mockListBackendServices.mockResolvedValueOnce([mockServices]);

			const result = await checkLoadBalancerLogging.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Backend service logging is not enabled");
		});
	});

	describe("Not Applicable Cases", () => {
		it("should return NOTAPPLICABLE when no backend services exist", async () => {
			mockListBackendServices.mockResolvedValueOnce([[]]);

			const result = await checkLoadBalancerLogging.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No HTTP(S) Load Balancer backend services found");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockListBackendServices.mockRejectedValueOnce(new Error("API Error"));

			const result = await checkLoadBalancerLogging.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking backend services");
		});

		it("should handle backend service without name", async () => {
			const mockServices = [
				{
					selfLink: "projects/test-project/global/backendServices/test-backend"
				}
			];

			mockListBackendServices.mockResolvedValueOnce([mockServices]);

			const result = await checkLoadBalancerLogging.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Backend service found without name");
		});
	});
});
