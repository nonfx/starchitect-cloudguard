import { NeptuneClient, DescribeDBClustersCommand } from "@aws-sdk/client-neptune";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkNeptuneEncryption(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new NeptuneClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all Neptune clusters
		const command = new DescribeDBClustersCommand({});
		const response = await client.send(command);

		if (!response.DBClusters || response.DBClusters.length === 0) {
			results.checks = [
				{
					resourceName: "No Neptune Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Neptune clusters found in the region"
				}
			];
			return results;
		}

		// Check encryption for each cluster
		for (const cluster of response.DBClusters) {
			if (!cluster.DBClusterIdentifier || !cluster.DBClusterArn) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without identifier or ARN"
				});
				continue;
			}

			results.checks.push({
				resourceName: cluster.DBClusterIdentifier,
				resourceArn: cluster.DBClusterArn,
				status: cluster.StorageEncrypted ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: cluster.StorageEncrypted ? undefined : "Neptune cluster is not encrypted at rest"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Neptune Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Neptune clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION || "ap-southeast-1";
	const results = await checkNeptuneEncryption(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon Neptune",
	shortServiceName: "neptune",
	title: "Ensure Data at Rest is Encrypted",
	description:
		"This helps ensure that the data is kept secure and protected when at rest. The user must choose from two key options which then determine when the data is encrypted at rest.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_9.2",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkNeptuneEncryption
} satisfies RuntimeTest;
