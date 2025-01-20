import { AlertPolicyServiceClient, protos } from "@google-cloud/monitoring";
import { v2 } from "@google-cloud/logging";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

type IAlertPolicy = protos.google.monitoring.v3.IAlertPolicy;
type ICondition = protos.google.monitoring.v3.AlertPolicy.ICondition;

interface IMetric {
	name?: string;
	filter?: string;
}

/**
 * Checks if log metric filters and alerts exist for project ownership changes.
 * This check ensures compliance with CIS Google Cloud Platform Foundation Benchmark v3.0.0 Section 2.4.
 *
 * @param projectId - The Google Cloud Project ID to check
 * @returns A compliance report detailing the status of metric filters and alerts for ownership changes
 */
async function checkProjectOwnershipMonitoring(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const monitoringClient = new AlertPolicyServiceClient();
	const loggingClient = new v2.MetricsServiceV2Client();
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Check log metric filter
		const [metrics] = await loggingClient.listLogMetrics({
			parent: `projects/${projectId}`
		});

		const expectedFilter =
			'(protoPayload.serviceName="cloudresourcemanager.googleapis.com") AND (ProjectOwnership OR projectOwnerInvitee) OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner") OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")';

		const ownershipMetric = metrics.find((metric: IMetric) => {
			const currentFilter = metric.filter?.trim() || "";

			// Check if the filter contains the key components
			const hasServiceName = currentFilter.includes(
				'serviceName="cloudresourcemanager.googleapis.com"'
			);
			const hasOwnershipCheck =
				currentFilter.includes("ProjectOwnership") || currentFilter.includes("projectOwnerInvitee");
			const hasRemoveAction =
				currentFilter.includes('action="REMOVE"') && currentFilter.includes('role="roles/owner"');
			const hasAddAction =
				currentFilter.includes('action="ADD"') && currentFilter.includes('role="roles/owner"');

			return (
				currentFilter === expectedFilter ||
				(hasServiceName && (hasOwnershipCheck || hasRemoveAction || hasAddAction))
			);
		});

		if (!ownershipMetric) {
			results.checks.push({
				resourceName: "Project Ownership Changes",
				status: ComplianceStatus.FAIL,
				message: "No valid log metric filter found for project ownership changes"
			});
			return results;
		}

		// Check for alert policy
		const [alertPolicies] = await monitoringClient.listAlertPolicies({
			name: `projects/${projectId}`
		});

		const validAlertPolicy = alertPolicies.find((policy: IAlertPolicy) => {
			return policy.conditions?.some((condition: ICondition) => {
				const threshold = condition.conditionThreshold;
				const expectedMetricType = `logging.googleapis.com/user/${ownershipMetric.name?.split("/").pop()}`;

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
				resourceName: "Project Ownership Changes",
				status: ComplianceStatus.FAIL,
				message: "No valid alert policy found for project ownership changes"
			});
			return results;
		}

		results.checks.push({
			resourceName: "Project Ownership Changes",
			status: ComplianceStatus.PASS,
			message: "Valid metric filter and alert policy exist for project ownership changes"
		});
	} catch (error) {
		results.checks.push({
			resourceName: "Project Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking project ownership monitoring: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main === true) {
	const projectId = process.env.GCP_PROJECT_ID;
	if (!projectId) {
		throw new Error("GOOGLE_CLOUD_PROJECT environment variable is required");
	}
	const results = await checkProjectOwnershipMonitoring(projectId);
	printSummary(generateSummary(results));
}

export default (<RuntimeTest>{
	title: "Ensure Log Metric Filter and Alerts Exist for Project Ownership Changes",
	description:
		"Monitor and alert on project ownership assignments/changes to prevent unauthorized access and maintain security compliance.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.4",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	execute: checkProjectOwnershipMonitoring,
	serviceName: "Cloud Logging",
	shortServiceName: "cloudlogging"
}) satisfies RuntimeTest;
