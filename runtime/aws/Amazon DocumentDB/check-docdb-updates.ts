import {
	DocDBClient,
	DescribeDBInstancesCommand,
	DescribeDBClustersCommand
} from "@aws-sdk/client-docdb";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkDocDBUpdatesCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new DocDBClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all DocumentDB clusters
		const clusters = await client.send(
			new DescribeDBClustersCommand({
				Filters: [
					{
						Name: "engine",
						Values: ["docdb"]
					}
				]
			})
		);

		if (!clusters.DBClusters || clusters.DBClusters.length === 0) {
			results.checks = [
				{
					resourceName: "No DocumentDB Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No DocumentDB clusters found in the region"
				}
			];
			return results;
		}

		// Check each cluster and its instances
		for (const cluster of clusters.DBClusters) {
			if (!cluster.DBClusterIdentifier) continue;

			try {
				// Get instances in the cluster
				const instances = await client.send(
					new DescribeDBInstancesCommand({
						Filters: [
							{
								Name: "db-cluster-id",
								Values: [cluster.DBClusterIdentifier]
							}
						]
					})
				);

				if (!instances.DBInstances || instances.DBInstances.length === 0) {
					results.checks.push({
						resourceName: cluster.DBClusterIdentifier,
						resourceArn: cluster.DBClusterArn,
						status: ComplianceStatus.FAIL,
						message: "No instances found in the cluster"
					});
					continue;
				}

				// Check each instance in the cluster
				for (const instance of instances.DBInstances) {
					if (!instance.DBInstanceIdentifier) continue;

					const pendingMaintenance =
						instance.PendingModifiedValues &&
						Object.keys(instance.PendingModifiedValues).length > 0;

					const autoMinorVersionUpgrade = instance.AutoMinorVersionUpgrade === true;

					if (pendingMaintenance) {
						results.checks.push({
							resourceName: instance.DBInstanceIdentifier,
							resourceArn: instance.DBInstanceArn,
							status: ComplianceStatus.FAIL,
							message: "Instance has pending maintenance updates that need to be applied"
						});
					} else if (!autoMinorVersionUpgrade) {
						results.checks.push({
							resourceName: instance.DBInstanceIdentifier,
							resourceArn: instance.DBInstanceArn,
							status: ComplianceStatus.FAIL,
							message: "Auto minor version upgrade is not enabled"
						});
					} else {
						results.checks.push({
							resourceName: instance.DBInstanceIdentifier,
							resourceArn: instance.DBInstanceArn,
							status: ComplianceStatus.PASS,
							message: undefined
						});
					}
				}
			} catch (error) {
				results.checks.push({
					resourceName: cluster.DBClusterIdentifier,
					resourceArn: cluster.DBClusterArn,
					status: ComplianceStatus.ERROR,
					message: `Error checking cluster instances: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking DocumentDB clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkDocDBUpdatesCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Regular Updates and Patches",
	description:
		"Stay informed about the latest security updates and patches released by Amazon for DocumentDB. Regularly apply updates and patches to your DocumentDB instances to protect against known vulnerabilities.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_7.7",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkDocDBUpdatesCompliance,
	serviceName: "Amazon DocumentDB",
	shortServiceName: "docdb"
} satisfies RuntimeTest;
