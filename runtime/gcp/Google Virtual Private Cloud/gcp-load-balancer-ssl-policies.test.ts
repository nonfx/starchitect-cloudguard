// @ts-nocheck
import {
	TargetHttpsProxiesClient,
	TargetSslProxiesClient,
	SslPoliciesClient
} from "@google-cloud/compute";
import { ComplianceStatus } from "../../types.js";
import checkLoadBalancerSslPolicies from "./gcp-load-balancer-ssl-policies.js";

describe("checkLoadBalancerSslPolicies", () => {
	const listHttpsProxies = jest.fn().mockResolvedValue([[]]);
	const listSslProxies = jest.fn().mockResolvedValue([[]]);
	const getSslPolicy = jest.fn().mockResolvedValue([{}]);

	beforeEach(() => {
		// Reset all mocks
		listHttpsProxies.mockClear();
		listSslProxies.mockClear();
		getSslPolicy.mockClear();

		// Default mock implementations
		TargetHttpsProxiesClient.prototype.list = listHttpsProxies;
		TargetSslProxiesClient.prototype.list = listSslProxies;
		SslPoliciesClient.prototype.get = getSslPolicy;
	});

	describe("Compliant Resources", () => {
		it("should return PASS for MODERN profile with TLS 1.2", async () => {
			const mockProxy = {
				name: "test-proxy",
				sslPolicy: "projects/test-project/global/sslPolicies/modern-policy"
			};
			const mockPolicy = {
				profile: "MODERN",
				minTlsVersion: "TLS_1_2"
			};

			listHttpsProxies.mockResolvedValueOnce([[mockProxy]]);
			getSslPolicy.mockResolvedValueOnce([mockPolicy]);

			const result = await checkLoadBalancerSslPolicies.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-proxy");
		});

		it("should return PASS for RESTRICTED profile", async () => {
			const mockProxy = {
				name: "test-proxy",
				sslPolicy: "projects/test-project/global/sslPolicies/restricted-policy"
			};
			const mockPolicy = {
				profile: "RESTRICTED"
			};

			listHttpsProxies.mockResolvedValueOnce([[mockProxy]]);
			getSslPolicy.mockResolvedValueOnce([mockPolicy]);

			const result = await checkLoadBalancerSslPolicies.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});

		it("should return PASS for CUSTOM profile without weak cipher suites", async () => {
			const mockProxy = {
				name: "test-proxy",
				sslPolicy: "projects/test-project/global/sslPolicies/custom-policy"
			};
			const mockPolicy = {
				profile: "CUSTOM",
				enabledFeatures: ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]
			};

			listHttpsProxies.mockResolvedValueOnce([[mockProxy]]);
			getSslPolicy.mockResolvedValueOnce([mockPolicy]);

			const result = await checkLoadBalancerSslPolicies.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no SSL policy is configured", async () => {
			const mockProxy = {
				name: "test-proxy"
			};

			listHttpsProxies.mockResolvedValueOnce([[mockProxy]]);

			const result = await checkLoadBalancerSslPolicies.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"No SSL policy configured - using insecure GCP default policy (TLS 1.0 with COMPATIBLE profile)"
			);
		});

		it("should return FAIL for CUSTOM profile with weak cipher suites", async () => {
			const mockProxy = {
				name: "test-proxy",
				sslPolicy: "projects/test-project/global/sslPolicies/custom-policy"
			};
			const mockPolicy = {
				profile: "CUSTOM",
				enabledFeatures: ["TLS_RSA_WITH_AES_128_CBC_SHA"]
			};

			listHttpsProxies.mockResolvedValueOnce([[mockProxy]]);
			getSslPolicy.mockResolvedValueOnce([mockPolicy]);

			const result = await checkLoadBalancerSslPolicies.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				`SSL policy 'custom-policy' does not meet security requirements: Must use either (a) MODERN profile with TLS 1.2, (b) RESTRICTED profile, or (c) CUSTOM profile without weak cipher suites`
			);
		});

		it("should return FAIL for MODERN profile without TLS 1.2", async () => {
			const mockProxy = {
				name: "test-proxy",
				sslPolicy: "projects/test-project/global/sslPolicies/modern-policy"
			};
			const mockPolicy = {
				profile: "MODERN",
				minTlsVersion: "TLS_1_1"
			};

			listHttpsProxies.mockResolvedValueOnce([[mockProxy]]);
			getSslPolicy.mockResolvedValueOnce([mockPolicy]);

			const result = await checkLoadBalancerSslPolicies.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				`SSL policy 'modern-policy' does not meet security requirements: Must use either (a) MODERN profile with TLS 1.2, (b) RESTRICTED profile, or (c) CUSTOM profile without weak cipher suites`
			);
		});
	});

	describe("Edge Cases", () => {
		it("should return ERROR when project ID is not provided", async () => {
			const result = await checkLoadBalancerSslPolicies.execute("");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Project ID is required but was not provided");
		});

		it("should return NOTAPPLICABLE when no load balancers exist", async () => {
			listHttpsProxies.mockResolvedValueOnce([[]]);
			listSslProxies.mockResolvedValueOnce([[]]);

			const result = await checkLoadBalancerSslPolicies.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No HTTPS or SSL proxy load balancers found");
		});

		it("should handle invalid SSL policy resource paths", async () => {
			const mockProxy = {
				name: "test-proxy",
				sslPolicy: "invalid-path"
			};

			listHttpsProxies.mockResolvedValueOnce([[mockProxy]]);

			const result = await checkLoadBalancerSslPolicies.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(
				"Error checking SSL policy: Invalid SSL policy resource path"
			);
		});
	});

	describe("Error Handling", () => {
		it("should handle API errors gracefully", async () => {
			listHttpsProxies.mockRejectedValueOnce(new Error("API Error"));

			const result = await checkLoadBalancerSslPolicies.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(
				"Error checking load balancer SSL policies: API Error"
			);
		});

		it("should handle SSL policy fetch errors", async () => {
			const mockProxy = {
				name: "test-proxy",
				sslPolicy: "projects/test-project/global/sslPolicies/error-policy"
			};

			listHttpsProxies.mockResolvedValueOnce([[mockProxy]]);
			getSslPolicy.mockRejectedValueOnce(new Error("Policy Fetch Error"));

			const result = await checkLoadBalancerSslPolicies.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking SSL policy: Policy Fetch Error");
		});

		it("should handle non-Error exceptions", async () => {
			listHttpsProxies.mockRejectedValueOnce("Unknown error");

			const result = await checkLoadBalancerSslPolicies.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(
				"Error checking load balancer SSL policies: Unknown error"
			);
		});
	});
});
