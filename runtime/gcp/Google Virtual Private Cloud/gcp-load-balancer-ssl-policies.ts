import {
	TargetHttpsProxiesClient,
	TargetSslProxiesClient,
	SslPoliciesClient
} from "@google-cloud/compute";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check if SSL policy is compliant based on CIS benchmark requirements
function isCompliantSslPolicy(policy: any): boolean {
	// Case 1: Modern profile with TLS 1.2
	if (policy.profile === "MODERN" && policy.minTlsVersion === "TLS_1_2") {
		return true;
	}

	// Case 2: Restricted profile (which enforces TLS 1.2 regardless of minTlsVersion)
	if (policy.profile === "RESTRICTED") {
		return true;
	}

	// Case 3: Custom profile without weak cipher suites
	if (policy.profile === "CUSTOM") {
		const weakCipherSuites = [
			"TLS_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_RSA_WITH_AES_128_CBC_SHA",
			"TLS_RSA_WITH_AES_256_CBC_SHA",
			"TLS_RSA_WITH_3DES_EDE_CBC_SHA"
		];

		// If any weak cipher suite is enabled, the policy is not compliant
		return !policy.enabledFeatures?.some((feature: string) => weakCipherSuites.includes(feature));
	}

	// Any other profile (e.g., COMPATIBLE) is not compliant
	return false;
}

// Main compliance check function
export async function checkLoadBalancerSslPolicies(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	if (!projectId) {
		return {
			checks: [
				{
					resourceName: "Load Balancer SSL Policy Check",
					status: ComplianceStatus.ERROR,
					message: "Project ID is required but was not provided"
				}
			]
		};
	}

	const httpsProxiesClient = new TargetHttpsProxiesClient();
	const sslProxiesClient = new TargetSslProxiesClient();
	const sslPoliciesClient = new SslPoliciesClient();

	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all HTTPS and SSL proxies
		const [httpsProxies] = await httpsProxiesClient.list({
			project: projectId
		});

		const [sslProxies] = await sslProxiesClient.list({
			project: projectId
		});

		if ((!httpsProxies || httpsProxies.length === 0) && (!sslProxies || sslProxies.length === 0)) {
			results.checks.push({
				resourceName: "Load Balancers",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No HTTPS or SSL proxy load balancers found"
			});
			return results;
		}

		// Check HTTPS proxies
		for (const proxy of httpsProxies) {
			const proxyName = proxy.name || "Unknown HTTPS Proxy";

			// If no SSL policy is configured, the GCP default policy is used (which is insecure)
			if (!proxy.sslPolicy) {
				results.checks.push({
					resourceName: proxyName,
					status: ComplianceStatus.FAIL,
					message:
						"No SSL policy configured - using insecure GCP default policy (TLS 1.0 with COMPATIBLE profile)"
				});
				continue;
			}

			try {
				// Validate SSL policy path format
				// Expected format: projects/PROJECT_ID/global/sslPolicies/POLICY_NAME
				if (!proxy.sslPolicy.match(/^projects\/[^/]+\/global\/sslPolicies\/[^/]+$/)) {
					throw new Error("Invalid SSL policy resource path");
				}

				const policyName = proxy.sslPolicy.split("/").pop();
				const [sslPolicy] = await sslPoliciesClient.get({
					project: projectId,
					sslPolicy: policyName
				});

				const isCompliant = isCompliantSslPolicy(sslPolicy);
				results.checks.push({
					resourceName: proxyName,
					status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isCompliant
						? undefined
						: `SSL policy '${policyName}' does not meet security requirements: Must use either (a) MODERN profile with TLS 1.2, (b) RESTRICTED profile, or (c) CUSTOM profile without weak cipher suites`
				});
			} catch (error) {
				results.checks.push({
					resourceName: proxyName,
					status: ComplianceStatus.ERROR,
					message: `Error checking SSL policy: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}

		// Check SSL proxies
		for (const proxy of sslProxies) {
			const proxyName = proxy.name || "Unknown SSL Proxy";

			// If no SSL policy is configured, the GCP default policy is used (which is insecure)
			if (!proxy.sslPolicy) {
				results.checks.push({
					resourceName: proxyName,
					status: ComplianceStatus.FAIL,
					message:
						"No SSL policy configured - using insecure GCP default policy (TLS 1.0 with COMPATIBLE profile)"
				});
				continue;
			}

			try {
				// Validate SSL policy path format
				// Expected format: projects/PROJECT_ID/global/sslPolicies/POLICY_NAME
				if (!proxy.sslPolicy.match(/^projects\/[^/]+\/global\/sslPolicies\/[^/]+$/)) {
					throw new Error("Invalid SSL policy resource path");
				}

				const policyName = proxy.sslPolicy.split("/").pop();
				const [sslPolicy] = await sslPoliciesClient.get({
					project: projectId,
					sslPolicy: policyName
				});

				const isCompliant = isCompliantSslPolicy(sslPolicy);
				results.checks.push({
					resourceName: proxyName,
					status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isCompliant
						? undefined
						: `SSL policy '${policyName}' does not meet security requirements: Must use either (a) MODERN profile with TLS 1.2, (b) RESTRICTED profile, or (c) CUSTOM profile without weak cipher suites`
				});
			} catch (error) {
				results.checks.push({
					resourceName: proxyName,
					status: ComplianceStatus.ERROR,
					message: `Error checking SSL policy: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Load Balancer SSL Policy Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking load balancer SSL policies: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const results = await checkLoadBalancerSslPolicies(projectId);
	printSummary(generateSummary(results));
}

// Export default with compliance check metadata
export default {
	title: "Ensure No HTTPS or SSL Proxy Load Balancers Permit SSL Policies With Weak Cipher Suites",
	description:
		"Secure Sockets Layer (SSL) policies determine what port Transport Layer Security (TLS) features clients are permitted to use when connecting to load balancers. To prevent usage of insecure features, SSL policies should use (a) at least TLS 1.2 with the MODERN profile; or (b) the RESTRICTED profile, because it effectively requires clients to use TLS 1.2 regardless of the chosen minimum TLS version; or (3) a CUSTOM profile that does not support weak cipher suites.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_3.9",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	serviceName: "VPC Network",
	shortServiceName: "vpc",
	execute: checkLoadBalancerSslPolicies
} satisfies RuntimeTest;
