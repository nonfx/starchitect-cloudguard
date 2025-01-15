import monitoring from "@google-cloud/monitoring";
import logging from "@google-cloud/logging";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { protos } from "@google-cloud/monitoring";

type AlertPolicy = protos.google.monitoring.v3.IAlertPolicy;
type Condition = protos.google.monitoring.v3.AlertPolicy.ICondition;

interface IMetric {
	name?: string;
	filter?: string;
}

/**
 * Checks if log metric filters and alerts exist for VPC network route changes.
 * This check ensures compliance with CIS Google Cloud Platform Foundation Benchmark v3.0.0 Section 2.8.
 *
 * @param projectId - The Google Cloud Project ID to check
 * @returns A compliance report detailing the status of metric filters and alerts for route changes
 */
async function checkVpcRouteChangesMonitoring(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const loggingClient = new logging.v2.MetricsServiceV2Client();
	const monitoringClient = new monitoring.v3.AlertPolicyServiceClient();
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all metric filters
		const [metrics] = await loggingClient.listMetrics({
			parent: `projects/${projectId}`
		});

		if (!metrics || metrics.length === 0) {
			results.checks.push({
				resourceName: "Log Metrics",
				status: ComplianceStatus.FAIL,
				message: "No log metric filters found"
			});
			return results;
		}

		// Check for VPC route changes metric filter
		const routeChangeMetrics = metrics.filter((metric: IMetric) => {
			const filter = metric.filter || "";
			return (
				filter.includes('resource.type="gce_route"') &&
				filter.includes('methodName="compute.routes.delete"') &&
				filter.includes('methodName="compute.routes.insert"')
			);
		});

		if (routeChangeMetrics.length === 0) {
			results.checks.push({
				resourceName: "VPC Route Changes Filter",
				status: ComplianceStatus.FAIL,
				message: "No metric filter exists for VPC route changes"
			});
			return results;
		}

		// Check for alert policy
		const [alertPolicies] = await monitoringClient.listAlertPolicies({
			name: `projects/${projectId}`
		});

		const hasValidAlert = routeChangeMetrics.every((metric: IMetric) => {
			return alertPolicies.some((policy: AlertPolicy) =>
				policy.conditions?.some((condition: Condition) => {
					const threshold = condition.conditionThreshold;
					return (
						threshold?.filter?.includes(metric.name || "") &&
						threshold?.comparison === "COMPARISON_GT" &&
						threshold?.thresholdValue === 0 &&
						threshold?.duration?.seconds === 0 &&
						threshold?.duration?.nanos === 0
					);
				})
			);
		});

		results.checks.push({
			resourceName: "VPC Route Changes Monitoring",
			status: hasValidAlert ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
			message: hasValidAlert
				? undefined
				: "One or more metrics do not have properly configured alert policies"
		});
	} catch (error) {
		results.checks.push({
			resourceName: "Monitoring Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking VPC route changes monitoring: ${
				error instanceof Error ? error.message : String(error)
			}`
		});
	}

	return results;
}

if (import.meta.main === true) {
	const projectId = process.env.GCP_PROJECT_ID;
	if (!projectId) {
		throw new Error("GOOGLE_CLOUD_PROJECT environment variable must be set");
	}
	const results = await checkVpcRouteChangesMonitoring(projectId);
	printSummary(generateSummary(results));
}

export default (<RuntimeTest>{
	title: "Ensure That the Log Metric Filter and Alerts Exist for VPC Network Route Changes",
	description:
		"Monitor VPC network route changes through log metric filters and alerts to ensure traffic flows through expected paths.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.8",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkVpcRouteChangesMonitoring,
	serviceName: "Cloud Logging",
	shortServiceName: "cloudlogging"
}) satisfies RuntimeTest;
