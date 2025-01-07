import { DocDBClient, DescribeDBClustersCommand } from "@aws-sdk/client-docdb";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkDocDBEncryptionInTransit(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new DocDBClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const command = new DescribeDBClustersCommand({});
		const response = await client.send(command);

		if (!response.DBClusters || response.DBClusters.length === 0) {
			results.checks = [
				{
					resourceName: "No DocumentDB Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No DocumentDB clusters found in the region"
				}
			];
			return results;
		}

		for (const cluster of response.DBClusters) {
			if (!cluster.DBClusterIdentifier || !cluster.DBClusterArn) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without identifier or ARN"
				});
				continue;
			}

			const isEncrypted = cluster.StorageEncrypted === true;

			results.checks.push({
				resourceName: cluster.DBClusterIdentifier,
				resourceArn: cluster.DBClusterArn,
				status: isEncrypted ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isEncrypted
					? undefined
					: "Encryption in transit is not enabled for this DocumentDB cluster"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking DocumentDB clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkDocDBEncryptionInTransit(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Encryption in Transit is Enabled",
	description:
		"Amazon Database DB uses SSL/TLS to encrypt data during transit. To secure your data in transit the individual should identify their client application and what is supported by TLS to configure it correctly",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_7.4",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkDocDBEncryptionInTransit,
	serviceName: "Amazon DocumentDB",
	shortServiceName: "docdb"
} satisfies RuntimeTest;
