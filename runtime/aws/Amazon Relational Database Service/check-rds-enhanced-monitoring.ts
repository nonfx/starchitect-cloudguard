import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Valid monitoring intervals in seconds
const VALID_INTERVALS = new Set([1, 5, 10, 15, 30, 60]);

async function checkRdsEnhancedMonitoring(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let marker: string | undefined;
		let instanceFound = false;

		do {
			const command = new DescribeDBInstancesCommand({
				Marker: marker
			});

			const response = await client.send(command);

			if (!response.DBInstances || response.DBInstances.length === 0) {
				if (!instanceFound) {
					results.checks = [
						{
							resourceName: "No RDS Instances",
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "No RDS instances found in the region"
						}
					];
					return results;
				}
				break;
			}

			for (const instance of response.DBInstances) {
				instanceFound = true;
				const instanceId = instance.DBInstanceIdentifier || "Unknown Instance";

				if (!instance.DBInstanceArn) {
					results.checks.push({
						resourceName: instanceId,
						status: ComplianceStatus.ERROR,
						message: "Instance ARN not found"
					});
					continue;
				}

				// Check monitoring interval
				const hasValidInterval =
					instance.MonitoringInterval && VALID_INTERVALS.has(instance.MonitoringInterval);
				// Check monitoring role
				const hasMonitoringRole =
					instance.MonitoringRoleArn && instance.MonitoringRoleArn.length > 0;

				if (!hasValidInterval || !hasMonitoringRole) {
					const message = [];
					if (!hasValidInterval) {
						message.push(
							`Invalid monitoring interval: ${instance.MonitoringInterval}. Must be one of: 1, 5, 10, 15, 30, or 60 seconds`
						);
					}
					if (!hasMonitoringRole) {
						message.push("Monitoring role ARN not configured");
					}

					results.checks.push({
						resourceName: instanceId,
						resourceArn: instance.DBInstanceArn,
						status: ComplianceStatus.FAIL,
						message: message.join("; ")
					});
				} else {
					results.checks.push({
						resourceName: instanceId,
						resourceArn: instance.DBInstanceArn,
						status: ComplianceStatus.PASS
					});
				}
			}

			marker = response.Marker;
		} while (marker);
	} catch (error) {
		results.checks = [
			{
				resourceName: "RDS Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking RDS instances: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkRdsEnhancedMonitoring(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Enhanced monitoring should be configured for RDS DB instances",
	description:
		"This control checks if enhanced monitoring is enabled for RDS DB instances with appropriate monitoring interval and role configuration.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.6",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsEnhancedMonitoring
} satisfies RuntimeTest;
