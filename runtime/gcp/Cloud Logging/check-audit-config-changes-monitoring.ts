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
 * Checks for the existence of log metric filters and alert policies monitoring audit configuration changes.
 * This check ensures compliance with CIS Google Cloud Platform Foundation Benchmark v3.0.0 Section 2.5.
 *
 * @param projectId - The Google Cloud Project ID to check
 * @returns A compliance report detailing the status of metric filters and alert policies
 */
async function checkAuditConfigChangesMonitoring(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const monitoringClient = new monitoring.v3.AlertPolicyServiceClient();
	const loggingClient = new logging.v2.MetricsServiceV2Client();
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Check for metric filter
		const [metrics] = await loggingClient.listMetrics({
			parent: `projects/${projectId}`
		});

		const auditMetric = metrics.find(
			(metric: IMetric) =>
				metric.filter ===
				'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*'
		);

		if (!auditMetric) {
			results.checks.push({
				resourceName: "Audit Config Changes Metric",
				status: ComplianceStatus.FAIL,
				message: "No metric filter found for audit configuration changes"
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
					threshold?.comparison === "COMPARISON_GT" &&
					threshold?.thresholdValue === 0 &&
					threshold?.duration?.seconds === 0 &&
					threshold?.duration?.nanos === 0
				);
			});
		});

		if (!validAlertPolicy) {
			results.checks.push({
				resourceName: "Audit Config Changes Alert",
				status: ComplianceStatus.FAIL,
				message: "No valid alert policy found for audit configuration changes"
			});
			return results;
		}

		results.checks.push({
			resourceName: "Audit Config Changes Monitoring",
			status: ComplianceStatus.PASS,
			message: "Valid metric filter and alert policy found for audit configuration changes"
		});
	} catch (error) {
		results.checks.push({
			resourceName: "Audit Config Changes Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking audit config monitoring: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main === true) {
	const projectId = process.env.GCP_PROJECT_ID;
	if (!projectId) {
		throw new Error("GOOGLE_CLOUD_PROJECT environment variable must be set");
	}
	const results = await checkAuditConfigChangesMonitoring(projectId);
	printSummary(generateSummary(results));
}

export default (<RuntimeTest>{
	title: "Ensure That the Log Metric Filter and Alerts Exist for Audit Configuration Changes",
	description:
		"Monitor and alert on GCP audit configuration changes using log metrics and alert policies for security compliance.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.5",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	execute: checkAuditConfigChangesMonitoring,
	serviceName: "Cloud Logging",
	shortServiceName: "cloudlogging"
}) satisfies RuntimeTest;
