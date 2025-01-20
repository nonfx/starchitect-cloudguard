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
 * Checks if log metric filters and alerts exist for VPC Network Firewall rule changes.
 * This check ensures compliance with CIS Google Cloud Platform Foundation Benchmark v3.0.0 Section 2.7.
 *
 * @param projectId - The Google Cloud Project ID to check
 * @returns A compliance report detailing the status of metric filters and alerts for firewall rule changes
 */
async function checkVpcFirewallRuleChanges(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const monitoringClient = new AlertPolicyServiceClient();
	const loggingClient = new v2.MetricsServiceV2Client();
	const results: ComplianceReport = { checks: [] };

	try {
		// Check log metric filters
		const [metrics] = await loggingClient.listLogMetrics({
			parent: `projects/${projectId}`
		});

		const expectedFilter =
			'resource.type="gce_firewall_rule" AND (protoPayload.methodName:"compute.firewalls.patch" OR protoPayload.methodName:"compute.firewalls.insert" OR protoPayload.methodName:"compute.firewalls.delete")';

		const firewallMetric = metrics.find((metric: IMetric) => {
			const currentFilter = metric.filter?.trim() || "";

			// Check if the filter contains the key components
			const hasResourceType = currentFilter.includes('resource.type="gce_firewall_rule"');
			const hasPatchMethod =
				currentFilter.includes('methodName:"compute.firewalls.patch"') ||
				currentFilter.includes('methodName="compute.firewalls.patch"');
			const hasInsertMethod =
				currentFilter.includes('methodName:"compute.firewalls.insert"') ||
				currentFilter.includes('methodName="compute.firewalls.insert"');
			const hasDeleteMethod =
				currentFilter.includes('methodName:"compute.firewalls.delete"') ||
				currentFilter.includes('methodName="compute.firewalls.delete"');

			return (
				currentFilter === expectedFilter ||
				(hasResourceType && (hasPatchMethod || hasInsertMethod || hasDeleteMethod))
			);
		});

		if (!firewallMetric) {
			results.checks.push({
				resourceName: "Log Metric Filter",
				status: ComplianceStatus.FAIL,
				message: "No valid metric filter found for VPC firewall rule changes"
			});
			return results;
		}

		// Check alert policies
		const [alertPolicies] = await monitoringClient.listAlertPolicies({
			name: `projects/${projectId}`
		});

		const validAlertPolicy = alertPolicies.find((policy: AlertPolicy) => {
			return policy.conditions?.some((condition: Condition) => {
				const threshold = condition.conditionThreshold;
				const expectedMetricType = `logging.googleapis.com/user/${firewallMetric.name?.split("/").pop()}`;

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
				resourceName: "VPC Firewall Rule Alert",
				status: ComplianceStatus.FAIL,
				message: "No alert policy found that monitors the firewall rule changes metric"
			});
			return results;
		}

		// If both metric filter and alert exist
		results.checks.push({
			resourceName: "VPC Firewall Rule Monitoring",
			status: ComplianceStatus.PASS,
			message: "Valid metric filter and alert policy exist for VPC firewall rule changes"
		});
	} catch (error) {
		results.checks.push({
			resourceName: "VPC Firewall Rule Monitoring",
			status: ComplianceStatus.ERROR,
			message: `Error checking firewall rule monitoring: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main === true) {
	const projectId = process.env.GCP_PROJECT_ID;
	if (!projectId) {
		throw new Error("GOOGLE_CLOUD_PROJECT environment variable must be set");
	}
	const results = await checkVpcFirewallRuleChanges(projectId);
	printSummary(generateSummary(results));
}

export default (<RuntimeTest>{
	title: "Ensure That the Log Metric Filter and Alerts Exist for VPC Network Firewall Rule Changes",
	description:
		"Monitor and alert on VPC Network Firewall rule changes through log metric filters for enhanced security visibility.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.7",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkVpcFirewallRuleChanges,
	serviceName: "Cloud Logging",
	shortServiceName: "cloudlogging"
}) satisfies RuntimeTest;
