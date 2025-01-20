import { AlertPolicyServiceClient, protos } from "@google-cloud/monitoring";
import { v2 } from "@google-cloud/logging";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";

type AlertPolicy = protos.google.monitoring.v3.IAlertPolicy;
type Condition = protos.google.monitoring.v3.AlertPolicy.ICondition;

interface IMetric {
	name?: string;
	filter?: string;
}

/**
 * Checks if log metric filters and alerts exist for VPC route changes.
 * This check ensures compliance with CIS Google Cloud Platform Foundation Benchmark v3.0.0 Section 2.8.
 *
 * @param projectId - The Google Cloud Project ID to check
 * @returns A compliance report detailing the status of metric filters and alerts for route changes
 */
async function checkVpcRouteChangesMonitoring(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const monitoringClient = new AlertPolicyServiceClient();
	const loggingClient = new v2.MetricsServiceV2Client();
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all metric filters
		const [metrics] = await loggingClient.listLogMetrics({
			parent: `projects/${projectId}`
		});

		const expectedFilter =
			'resource.type="gce_route" AND (protoPayload.methodName:"compute.routes.delete" OR protoPayload.methodName:"compute.routes.insert")';

		const routeChangeMetrics = metrics.find((metric: IMetric) => {
			const currentFilter = metric.filter?.trim() || "";

			// Check if the filter contains the key components
			const hasResourceType = currentFilter.includes('resource.type="gce_route"');
			const hasDeleteMethod =
				currentFilter.includes('methodName:"compute.routes.delete"') ||
				currentFilter.includes('methodName="compute.routes.delete"');
			const hasInsertMethod =
				currentFilter.includes('methodName:"compute.routes.insert"') ||
				currentFilter.includes('methodName="compute.routes.insert"');

			return (
				currentFilter === expectedFilter ||
				(hasResourceType && (hasDeleteMethod || hasInsertMethod))
			);
		});

		if (!routeChangeMetrics) {
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

		const validAlertPolicy = alertPolicies.find((policy: AlertPolicy) => {
			return policy.conditions?.some((condition: Condition) => {
				const threshold = condition.conditionThreshold;
				const expectedMetricType = `logging.googleapis.com/user/${routeChangeMetrics.name?.split("/").pop()}`;

				const hasValidFilter = threshold?.filter?.includes(expectedMetricType);
				const hasValidComparison = threshold?.comparison === "COMPARISON_GT";
				const hasValidThreshold = Number(threshold?.thresholdValue) === 0;
				const hasValidDuration =
					Number(threshold?.duration?.seconds) === 0 && Number(threshold?.duration?.nanos) === 0;

				return hasValidFilter && hasValidComparison && hasValidThreshold && hasValidDuration;
			});
		});

		if (!validAlertPolicy) {
			results.checks.push({
				resourceName: "VPC Route Changes Alert",
				status: ComplianceStatus.FAIL,
				message: "No valid alert policy found for VPC route changes"
			});
			return results;
		}

		results.checks.push({
			resourceName: "VPC Route Changes Monitoring",
			status: ComplianceStatus.PASS,
			message: "Valid metric filter and alert policy exist for VPC route changes"
		});
	} catch (error) {
		results.checks.push({
			resourceName: "Monitoring Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking VPC route changes monitoring: ${error instanceof Error ? error.message : String(error)}`
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
