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
 * Checks if log metric filters and alerts exist for SQL instance configuration changes.
 * This check ensures compliance with CIS Google Cloud Platform Foundation Benchmark v3.0.0 Section 2.11.
 *
 * @param projectId - The Google Cloud Project ID to check
 * @returns A compliance report detailing the status of metric filters and alerts for SQL config changes
 */
async function checkSqlInstanceConfigChanges(
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

		const sqlConfigMetric = metrics.find(
			(metric: IMetric) =>
				metric.filter ===
				'resource.type="cloudsql_database" AND protoPayload.methodName="cloudsql.instances.update"'
		);

		if (!sqlConfigMetric) {
			results.checks.push({
				resourceName: "SQL Config Change Metric",
				status: ComplianceStatus.FAIL,
				message: "No metric filter found for SQL instance configuration changes"
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
					threshold?.filter?.includes(sqlConfigMetric.name || "") &&
					threshold?.comparison === "COMPARISON_GT" &&
					threshold?.thresholdValue === 0 &&
					threshold?.duration?.seconds === 0 &&
					threshold?.duration?.nanos === 0
				);
			});
		});

		if (!validAlertPolicy) {
			results.checks.push({
				resourceName: "SQL Config Change Alert",
				status: ComplianceStatus.FAIL,
				message: "No alert policy found for SQL instance configuration changes"
			});
			return results;
		}

		// Both metric and alert exist and are properly configured
		results.checks.push({
			resourceName: "SQL Config Change Monitoring",
			status: ComplianceStatus.PASS,
			message: "Metric filter and alert policy are properly configured"
		});
	} catch (error) {
		results.checks.push({
			resourceName: "SQL Config Change Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking SQL config change monitoring: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main === true) {
	const projectId = process.env.GCP_PROJECT_ID;
	if (!projectId) {
		throw new Error("GOOGLE_CLOUD_PROJECT environment variable must be set");
	}
	const results = await checkSqlInstanceConfigChanges(projectId);
	printSummary(generateSummary(results));
}

export default (<RuntimeTest>{
	title: "Ensure Log Metric Filter and Alerts Exist for SQL Instance Configuration Changes",
	description:
		"Monitor SQL instance configuration changes through metric filters and alerts to detect and respond to security-impacting modifications.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.11",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkSqlInstanceConfigChanges,
	serviceName: "Cloud Logging",
	shortServiceName: "cloudlogging"
}) satisfies RuntimeTest;
