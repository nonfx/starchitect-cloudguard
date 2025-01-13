import { FirewallsClient } from "@google-cloud/compute";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check if rule allows unrestricted SSH access
export function hasUnrestrictedSSH(rule: any): boolean {
	if (rule.direction !== "INGRESS") return false;

	// Check if rule has source range 0.0.0.0/0
	const hasUnrestrictedSource = rule.sourceRanges?.includes("0.0.0.0/0");
	if (!hasUnrestrictedSource) return false;

	// Check if rule allows TCP port 22
	return rule.allowed?.some((allow: any) => {
		return (
			allow.IPProtocol === "tcp" &&
			allow.ports?.some(
				(port: string) => port === "22" || (port.includes("-") && isPortInRange(22, port))
			)
		);
	});
}

// Helper function to check if port is in range
export function isPortInRange(port: number, range: string): boolean {
	// Trim and validate the input range
	const trimmedRange = range.trim();

	// If no hyphen, check for exact port match
	if (!trimmedRange.includes("-")) {
		const singlePort = Number(trimmedRange);
		return !isNaN(singlePort) && port === singlePort;
	}

	// Split the range
	const parts = trimmedRange.split("-");

	// Ensure we have exactly two parts
	if (parts.length !== 2) {
		return false;
	}

	// Safely destructure and convert to numbers
	const startStr = parts[0]?.trim();
	const endStr = parts[1]?.trim();

	// Validate both parts exist and can be converted to numbers
	if (!startStr || !endStr) {
		return false;
	}

	const start = Number(startStr);
	const end = Number(endStr);

	// Validate the conversion
	if (isNaN(start) || isNaN(end)) {
		return false;
	}

	// Check if port is within the range
	return port >= Math.min(start, end) && port <= Math.max(start, end);
}

// Main compliance check function
export async function checkSSHRestrictions(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const client = new FirewallsClient();
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// List all firewall rules in the project
		const [rules] = await client.list({
			project: projectId
		});

		// No rules found
		if (!rules || rules.length === 0) {
			results.checks.push({
				resourceName: "GCP Firewall Rules",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No firewall rules found in the project"
			});
			return results;
		}

		// Check each firewall rule
		for (const rule of rules) {
			const ruleName = rule.name || "Unknown Rule";
			const selfLink = rule.selfLink || undefined;

			if (hasUnrestrictedSSH(rule)) {
				results.checks.push({
					resourceName: ruleName,
					resourceArn: selfLink,
					status: ComplianceStatus.FAIL,
					message: `Firewall rule allows unrestricted SSH access (port 22) from the internet (0.0.0.0/0). Restrict source IP ranges for SSH access.`
				});
			} else {
				results.checks.push({
					resourceName: ruleName,
					resourceArn: selfLink,
					status: ComplianceStatus.PASS
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "SSH Restrictions Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking SSH restrictions: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const results = await checkSSHRestrictions(projectId);
	printSummary(generateSummary(results));
}

// Export default with compliance check metadata
export default {
	title: "Ensure That SSH Access Is Restricted From the Internet",
	description:
		"GCP Firewall Rules should restrict SSH access from the internet (0.0.0.0/0) to maintain security of VPC networks and instances.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_3.6",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	execute: checkSSHRestrictions,
	serviceName: "VPC Firewall Rules",
	shortServiceName: "firewall"
} satisfies RuntimeTest;
