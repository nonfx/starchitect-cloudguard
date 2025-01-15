import compute from "@google-cloud/compute";
import { GoogleAuth } from "google-auth-library";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface Policy {
	enableLogging?: boolean;
	networks?: Array<{ networkUrl?: string }>;
}

interface DnsResponse {
	policies?: Policy[];
}

type Network = {
	name?: string;
	selfLink?: string;
};

/**
 * Checks if Cloud DNS logging is enabled for all VPC networks in a GCP project.
 * This check ensures compliance with CIS Google Cloud Platform Foundation Benchmark v3.0.0 Section 2.12.
 *
 * @param projectId - The Google Cloud Project ID to check
 * @returns A compliance report detailing the DNS logging status for each VPC network
 */
async function checkDnsLoggingEnabled(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const computeClient = new compute.v1.NetworksClient();
	const auth = new GoogleAuth({
		scopes: ["https://www.googleapis.com/auth/cloud-platform"]
	});
	const client = await auth.getClient();
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all VPC networks
		const [networks] = await computeClient.list({
			project: projectId
		});

		if (!networks || networks.length === 0) {
			results.checks = [
				{
					resourceName: "No VPC Networks",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No VPC networks found in the project"
				}
			];
			return results;
		}

		// Get all DNS policies
		// Get all DNS policies using the REST API
		const response = await client.request<DnsResponse>({
			url: `https://dns.googleapis.com/dns/v1/projects/${projectId}/policies`,
			method: "GET"
		});

		const policies = (response.data as DnsResponse)?.policies || [];

		// Check each network for DNS logging
		for (const network of networks) {
			if (!network.name) {
				results.checks.push({
					resourceName: "Unknown Network",
					status: ComplianceStatus.ERROR,
					message: "Network found without name"
				});
				continue;
			}

			// Check if network has an associated DNS policy with logging enabled
			const hasLogging =
				(policies || []).some(
					(policy: Policy) =>
						policy.enableLogging === true &&
						policy.networks?.some(
							(net: { networkUrl?: string }) => net.networkUrl === network.selfLink
						)
				) ?? false;

			results.checks.push({
				resourceName: network.name?.toString() || "Unknown Network",
				resourceArn: network.selfLink?.toString(),
				status: hasLogging ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasLogging ? undefined : "Cloud DNS logging is not enabled for this VPC network"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Project Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking DNS logging: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main === true) {
	const projectId = process.env.GCP_PROJECT_ID;
	if (!projectId) {
		throw new Error("GOOGLE_CLOUD_PROJECT environment variable must be set");
	}
	const results = await checkDnsLoggingEnabled(projectId);
	printSummary(generateSummary(results));
}

export default (<RuntimeTest>{
	title: "Ensure That Cloud DNS Logging Is Enabled for All VPC Networks",
	description:
		"Cloud DNS logging records the queries from the name servers within your VPC to Stackdriver. Logged queries can come from Compute Engine VMs, GKE containers, or other GCP resources provisioned within the VPC.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.12",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkDnsLoggingEnabled,
	serviceName: "Cloud Logging",
	shortServiceName: "cloudlogging"
}) satisfies RuntimeTest;
