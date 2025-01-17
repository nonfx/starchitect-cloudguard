import { AlertPolicyServiceClient, protos } from "@google-cloud/monitoring";
import { v2 } from "@google-cloud/logging";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";

type AlertPolicy = protos.google.monitoring.v3.IAlertPolicy;
type Condition = protos.google.monitoring.v3.AlertPolicy.ICondition;

interface IMetric {
	filter?: string;
	name?: string;
}

/**
 * Checks if log metric filters and alerts exist for IAM custom role changes.
 * This check ensures compliance with CIS Google Cloud Platform Foundation Benchmark v3.0.0 Section 2.6.
 *
 * @param projectId - The Google Cloud Project ID to check
 * @returns A compliance report detailing the status of metric filters and alerts for role changes
 */
async function checkLogMetricRoleChanges(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const monitoringClient = new AlertPolicyServiceClient();
	const loggingClient = new v2.MetricsServiceV2Client();
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Check for metric filter
		const [metrics] = await loggingClient.listLogMetrics({
			parent: `projects/${projectId}`
		});

		const roleMetric = metrics.find(
			(metric: IMetric) =>
				metric.filter ===
				'protoPayload.methodName="CreateRole" OR protoPayload.methodName="DeleteRole" OR protoPayload.methodName="UpdateRole"'
		);

		if (!roleMetric) {
			results.checks.push({
				resourceName: "Role Changes Metric",
				status: ComplianceStatus.FAIL,
				message: "No metric filter found for IAM role changes"
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
				return (
					threshold?.filter?.includes(roleMetric.name || "") &&
					threshold?.comparison === "COMPARISON_GT" &&
					threshold?.thresholdValue === 0 &&
					threshold?.duration?.seconds === 0 &&
					threshold?.duration?.nanos === 0
				);
			});
		});

		if (!validAlertPolicy) {
			results.checks.push({
				resourceName: "Role Changes Alert",
				status: ComplianceStatus.FAIL,
				message: "No valid alert policy found for IAM role changes"
			});
			return results;
		}

		results.checks.push({
			resourceName: "Role Changes Monitoring",
			status: ComplianceStatus.PASS,
			message: "Valid metric filter and alert policy found for IAM role changes"
		});
	} catch (error) {
		results.checks.push({
			resourceName: "Role Changes Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking role changes monitoring: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main === true) {
	const projectId = process.env.GCP_PROJECT_ID;
	if (!projectId) {
		throw new Error("GOOGLE_CLOUD_PROJECT environment variable must be set");
	}
	const results = await checkLogMetricRoleChanges(projectId);
	printSummary(generateSummary(results));
}

export default (<RuntimeTest>{
	title: "Ensure That the Log Metric Filter and Alerts Exist for Custom Role Changes",
	description:
		"Monitor IAM role changes through metric filters and alerts to detect unauthorized or suspicious role modifications.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.6",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	execute: checkLogMetricRoleChanges,
	serviceName: "Cloud Logging",
	shortServiceName: "cloudlogging"
}) satisfies RuntimeTest;
