import compute from "@google-cloud/compute";
import type { protos } from "@google-cloud/compute";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

type BackendService = protos.google.cloud.compute.v1.IBackendService;

/**
 * Checks if logging is enabled for HTTP(S) Load Balancer backend services.
 * This check ensures compliance with CIS Google Cloud Platform Foundation Benchmark v3.0.0 Section 2.16.
 *
 * @param projectId - The Google Cloud Project ID to check
 * @param region - The region to check (defaults to 'global')
 * @returns A compliance report detailing the logging status for each backend service
 */
async function checkLoadBalancerLoggingCompliance(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const client = new compute.v1.BackendServicesClient();
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all backend services
		const [backendServices] = await client.list({
			project: projectId,
			maxResults: 1000
		});

		if (!backendServices || backendServices.length === 0) {
			results.checks = [
				{
					resourceName: "No Backend Services",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No HTTP(S) Load Balancer backend services found"
				}
			];
			return results;
		}

		// Check each backend service for logging configuration
		for (const service of backendServices) {
			if (!service.name) {
				results.checks.push({
					resourceName: "Unknown Backend Service",
					status: ComplianceStatus.ERROR,
					message: "Backend service found without name"
				});
				continue;
			}

			const logConfig = service.logConfig;
			const hasValidLogging =
				logConfig?.enable === true &&
				typeof logConfig?.sampleRate === "number" &&
				logConfig.sampleRate > 0;

			const message = !hasValidLogging
				? logConfig?.enable !== true
					? "Backend service logging is not enabled"
					: !logConfig?.sampleRate || logConfig.sampleRate <= 0
						? "Backend service logging sample rate must be greater than 0"
						: "Backend service logging is not properly configured"
				: undefined;

			results.checks.push({
				resourceName: service.name,
				resourceArn: service.selfLink || undefined,
				status: hasValidLogging ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Backend Services Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking backend services: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main === true) {
	const projectId = process.env.GCP_PROJECT_ID;
	if (!projectId) {
		throw new Error("GOOGLE_CLOUD_PROJECT environment variable must be set");
	}
	const results = await checkLoadBalancerLoggingCompliance(projectId);
	printSummary(generateSummary(results));
}

export default (<RuntimeTest>{
	title: "Ensure Logging is enabled for HTTP(S) Load Balancer",
	description:
		"Logging enabled on a HTTPS Load Balancer will show all network traffic and its destination. This helps in monitoring and analyzing traffic patterns and potential security issues.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.16",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkLoadBalancerLoggingCompliance,
	serviceName: "Cloud Logging",
	shortServiceName: "cloudlogging"
}) satisfies RuntimeTest;
