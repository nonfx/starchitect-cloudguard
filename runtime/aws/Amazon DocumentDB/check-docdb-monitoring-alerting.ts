import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import {
	DocDBClient,
	DescribeDBClustersCommand,
	DescribeDBInstancesCommand
} from "@aws-sdk/client-docdb";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkDocDBMonitoringAlerting(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const cwClient = new CloudWatchClient({ region });
	const docdbClient = new DocDBClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all DocumentDB clusters
		const clusters = await docdbClient.send(new DescribeDBClustersCommand({}));

		// Get all DocumentDB instances
		const instances = await docdbClient.send(new DescribeDBInstancesCommand({}));

		// Get all CloudWatch alarms
		const alarms = await cwClient.send(new DescribeAlarmsCommand({}));

		// Only add NOTAPPLICABLE check if there are no resources at all
		if (!clusters.DBClusters?.length && !instances.DBInstances?.length) {
			results.checks.push({
				resourceName: "DocumentDB",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No DocumentDB clusters or instances found"
			});
			return results;
		}

		const validClusters = clusters.DBClusters?.filter(c => c.DBClusterIdentifier) || [];
		const validInstances = instances.DBInstances?.filter(i => i.DBInstanceIdentifier) || [];

		// If we have resources but none are valid, return empty checks array
		if (!validClusters.length && !validInstances.length) {
			return results;
		}

		// Check clusters
		for (const cluster of validClusters) {
			const clusterAlarms = alarms.MetricAlarms?.filter(alarm =>
				alarm.Dimensions?.some(
					dim => dim.Name === "DBClusterIdentifier" && dim.Value === cluster.DBClusterIdentifier
				)
			);

			results.checks.push({
				resourceName: cluster.DBClusterIdentifier!,
				resourceArn: cluster.DBClusterArn,
				status: clusterAlarms?.length ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: clusterAlarms?.length
					? undefined
					: "No CloudWatch alarms configured for this DocumentDB cluster"
			});
		}

		// Check instances
		for (const instance of validInstances) {
			const instanceAlarms = alarms.MetricAlarms?.filter(alarm =>
				alarm.Dimensions?.some(
					dim => dim.Name === "DBInstanceIdentifier" && dim.Value === instance.DBInstanceIdentifier
				)
			);

			results.checks.push({
				resourceName: instance.DBInstanceIdentifier!,
				resourceArn: instance.DBInstanceArn,
				status: instanceAlarms?.length ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: instanceAlarms?.length
					? undefined
					: "No CloudWatch alarms configured for this DocumentDB instance"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "DocumentDB Monitoring Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking DocumentDB monitoring: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkDocDBMonitoringAlerting(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure to Implement Monitoring and Alerting - Alerting",
	description:
		"This helps by alerting the system if any unusual event has occurred or if a particular threshold has been achieved because the user is able to set a desired interval or the cluster. This then allows system administrators to swiftly correct the situation and avoid subsequent complications if something unusual is happening",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_7.8_b",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkDocDBMonitoringAlerting,
	serviceName: "Amazon DocumentDB",
	shortServiceName: "docdb"
} satisfies RuntimeTest;
