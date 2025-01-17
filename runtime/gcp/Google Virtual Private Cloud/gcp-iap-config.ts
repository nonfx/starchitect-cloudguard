import { FirewallsClient, BackendServicesClient } from "@google-cloud/compute";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check if firewall rule allows only IAP and health check IPs
function isCompliantRule(rule: any): boolean {
	// Expected source IP ranges
	const allowedIPs = [
		"35.235.240.0/20", // IAP Proxy Addresses
		"130.211.0.0/22", // Google Health Check
		"35.191.0.0/16" // Google Health Check
	];

	// Check if rule has exactly the allowed source ranges
	const sourceRanges: string[] = rule.sourceRanges || [];
	if (
		!sourceRanges.every((ip: string) => allowedIPs.includes(ip)) ||
		!allowedIPs.every((ip: string) => sourceRanges.includes(ip))
	) {
		return false;
	}

	// Check if ports are restricted to 80 and 443
	const allowed: Array<{ IPProtocol?: string; ports?: string[] }> = rule.allowed || [];
	if (allowed.length === 0) return false;

	return allowed.every(allow => {
		if (allow.IPProtocol !== "tcp") return false;
		const ports: string[] = allow.ports || [];
		if (ports.length === 0) return false;
		return ports.every(port => ["80", "443"].includes(port));
	});
}

// Helper function to check if IAP is enabled for any backend service
async function hasIAPEnabledBackends(
	client: BackendServicesClient,
	projectId: string
): Promise<boolean> {
	try {
		const [services] = await client.list({
			project: projectId
		});

		return services.some(service => service.iap && service.iap.enabled === true);
	} catch (error) {
		throw new Error(
			`Failed to check IAP status: ${error instanceof Error ? error.message : String(error)}`
		);
	}
}

// Main compliance check function
export async function checkIAPCompliance(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	if (!projectId) {
		return {
			checks: [
				{
					resourceName: "IAP Compliance Check",

					status: ComplianceStatus.ERROR,
					message: "Project ID is required but was not provided"
				}
			]
		};
	}

	const firewallsClient = new FirewallsClient();
	const backendServicesClient = new BackendServicesClient();
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// First check if IAP is enabled for any backend services
		const iapEnabled = await hasIAPEnabledBackends(backendServicesClient, projectId);

		if (!iapEnabled) {
			results.checks.push({
				resourceName: "IAP Configuration",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "IAP is not enabled for any backend services"
			});
			return results;
		}

		// If IAP is enabled, check firewall rules
		const [rules] = await firewallsClient.list({
			project: projectId
		});

		if (!rules || rules.length === 0) {
			results.checks.push({
				resourceName: "GCP Firewall Rules",
				status: ComplianceStatus.FAIL,
				message:
					"No firewall rules found but IAP is enabled. Rules should be configured to allow traffic from IAP proxy and health check IPs."
			});
			return results;
		}

		// Check each firewall rule
		let hasCompliantRule = false;
		for (const rule of rules) {
			const ruleName = rule.name || "Unknown Rule";
			const selfLink = rule.selfLink || undefined;

			const isCompliant = isCompliantRule(rule);
			if (isCompliant) {
				hasCompliantRule = true;
			}

			results.checks.push({
				resourceName: ruleName,
				resourceArn: selfLink,
				status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: !isCompliant
					? "Firewall rule does not comply with IAP requirements. Should only allow traffic from IAP proxy (35.235.240.0/20) and health check IPs (130.211.0.0/22, 35.191.0.0/16) on ports 80 and 443."
					: undefined
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "IAP Compliance Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking IAP compliance: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const results = await checkIAPCompliance(projectId);
	printSummary(generateSummary(results));
}

// Export default with compliance check metadata
export default {
	title:
		"Use Identity Aware Proxy (IAP) to Ensure Only Traffic From Google IP Addresses are 'Allowed'",
	description:
		"IAP authenticates the user requests to your apps via a Google single sign in. You can then manage these users with permissions to control access. It is recommended to use both IAP permissions and firewalls to restrict this access to your apps with sensitive information.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_3.1o",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	serviceName: "VPC Network",
	shortServiceName: "vpc",
	execute: checkIAPCompliance
} satisfies RuntimeTest;
