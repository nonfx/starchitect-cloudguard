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
 * Checks if log metric filters and alerts exist for VPC network changes.
 * This check ensures compliance with CIS Google Cloud Platform Foundation Benchmark v3.0.0 Section 2.9.
 *
 * @param projectId - The Google Cloud Project ID to check
 * @returns A compliance report detailing the status of metric filters and alerts for VPC network changes
 */
async function checkVpcNetworkChangesMonitoring(
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

		const expectedFilter =
			'resource.type="gce_network" AND (protoPayload.methodName:"compute.networks.insert" OR protoPayload.methodName:"compute.networks.patch" OR protoPayload.methodName:"compute.networks.delete" OR protoPayload.methodName:"compute.networks.removePeering" OR protoPayload.methodName:"compute.networks.addPeering")';

		const vpcNetworkMetric = metrics.find((metric: IMetric) => {
			const currentFilter = metric.filter?.trim() || "";

			// Check if the filter contains the key components
			const hasResourceType = currentFilter.includes('resource.type="gce_network"');
			const hasInsertMethod =
				currentFilter.includes('methodName:"compute.networks.insert"') ||
				currentFilter.includes('methodName="compute.networks.insert"');
			const hasPatchMethod =
				currentFilter.includes('methodName:"compute.networks.patch"') ||
				currentFilter.includes('methodName="compute.networks.patch"');
			const hasDeleteMethod =
				currentFilter.includes('methodName:"compute.networks.delete"') ||
				currentFilter.includes('methodName="compute.networks.delete"');
			const hasRemovePeeringMethod =
				currentFilter.includes('methodName:"compute.networks.removePeering"') ||
				currentFilter.includes('methodName="compute.networks.removePeering"');
			const hasAddPeeringMethod =
				currentFilter.includes('methodName:"compute.networks.addPeering"') ||
				currentFilter.includes('methodName="compute.networks.addPeering"');

			return (
				currentFilter === expectedFilter ||
				(hasResourceType &&
					(hasInsertMethod ||
						hasPatchMethod ||
						hasDeleteMethod ||
						hasRemovePeeringMethod ||
						hasAddPeeringMethod))
			);
		});

		if (!vpcNetworkMetric) {
			results.checks.push({
				resourceName: "VPC Network Changes Metric",
				status: ComplianceStatus.FAIL,
				message: "No metric filter found for VPC network changes"
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
				const expectedMetricType = `logging.googleapis.com/user/${vpcNetworkMetric.name?.split("/").pop()}`;

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
				resourceName: "VPC Network Changes Alert",
				status: ComplianceStatus.FAIL,
				message: "No valid alert policy found for VPC network changes"
			});
			return results;
		}

		results.checks.push({
			resourceName: "VPC Network Changes Monitoring",
			status: ComplianceStatus.PASS,
			message: "Valid metric filter and alert policy exist for VPC network changes"
		});
	} catch (error) {
		results.checks.push({
			resourceName: "VPC Network Changes Monitoring",
			status: ComplianceStatus.ERROR,
			message: `Error checking VPC network changes monitoring: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main === true) {
	const projectId = process.env.GCP_PROJECT_ID;
	if (!projectId) {
		throw new Error("GOOGLE_CLOUD_PROJECT environment variable must be set");
	}
	const results = await checkVpcNetworkChangesMonitoring(projectId);
	printSummary(generateSummary(results));
}

export default (<RuntimeTest>{
	title: "Ensure That the Log Metric Filter and Alerts Exist for VPC Network Changes",
	description:
		"Monitor VPC network changes through log metric filters and alerts to ensure network traffic security and integrity.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.9",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkVpcNetworkChangesMonitoring,
	serviceName: "Cloud Logging",
	shortServiceName: "cloudlogging"
}) satisfies RuntimeTest;
