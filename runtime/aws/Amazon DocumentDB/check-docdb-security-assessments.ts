import { DocDBClient, DescribeDBInstancesCommand } from "@aws-sdk/client-docdb";
import { getAllDocDBClusters } from "./get-all-docdb-clusters.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkDocDBSecurityAssessments(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new DocDBClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all DocumentDB clusters using pagination
		const clusters =
			(await getAllDocDBClusters(client, [
				{
					Name: "engine",
					Values: ["docdb"]
				}
			])) ?? [];

		if (clusters.length === 0) {
			results.checks = [
				{
					resourceName: "No DocumentDB Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No DocumentDB clusters found in the region"
				}
			];
			return results;
		}

		// Check each cluster
		for (const cluster of clusters) {
			if (!cluster.DBClusterIdentifier || !cluster.DBClusterArn) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without identifier or ARN"
				});
				continue;
			}

			try {
				// Try to get cluster instances, but don't fail if this errors
				try {
					await client.send(
						new DescribeDBInstancesCommand({
							Filters: [
								{
									Name: "db-cluster-id",
									Values: [cluster.DBClusterIdentifier]
								}
							]
						})
					);
				} catch (instanceError) {
					// Ignore instance-related errors since they don't affect cluster security config
					console.warn(
						`Failed to get instances for cluster ${cluster.DBClusterIdentifier}: ${instanceError}`
					);
				}

				// Check security configuration
				const isCompliant =
					cluster.StorageEncrypted &&
					cluster.DeletionProtection &&
					(cluster.VpcSecurityGroups?.length ?? 0) > 0;

				results.checks.push({
					resourceName: cluster.DBClusterIdentifier,
					resourceArn: cluster.DBClusterArn,
					status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isCompliant ? undefined : "Cluster missing required security configurations"
				});
			} catch (error) {
				results.checks.push({
					resourceName: cluster.DBClusterIdentifier,
					resourceArn: cluster.DBClusterArn,
					status: ComplianceStatus.ERROR,
					message: `Error checking cluster security: ${error instanceof Error ? error.message : String(error)}`
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
	const results = await checkDocDBSecurityAssessments(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure to Conduct Security Assessments",
	description:
		"Periodically perform security assessments, including vulnerability assessments and penetration testing, to identify and address any security weaknesses. Review your security configuration against best practices and industry standards",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_7.11",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkDocDBSecurityAssessments,
	serviceName: "Amazon DocumentDB",
	shortServiceName: "docdb"
} satisfies RuntimeTest;
