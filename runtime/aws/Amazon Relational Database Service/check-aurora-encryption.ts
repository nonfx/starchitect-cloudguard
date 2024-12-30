import { RDSClient, DescribeDBClustersCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkAuroraEncryption(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all Aurora clusters
		const command = new DescribeDBClustersCommand({});
		const response = await client.send(command);

		if (!response.DBClusters || response.DBClusters.length === 0) {
			results.checks = [
				{
					resourceName: "No Aurora Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Aurora clusters found in the region"
				}
			];
			return results;
		}

		// Check each cluster for encryption
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
			const hasKmsKey = cluster.KmsKeyId !== undefined && cluster.KmsKeyId !== "";

			if (!isEncrypted) {
				results.checks.push({
					resourceName: cluster.DBClusterIdentifier,
					resourceArn: cluster.DBClusterArn,
					status: ComplianceStatus.FAIL,
					message: "Aurora cluster does not have encryption at rest enabled"
				});
			} else if (!hasKmsKey) {
				results.checks.push({
					resourceName: cluster.DBClusterIdentifier,
					resourceArn: cluster.DBClusterArn,
					status: ComplianceStatus.FAIL,
					message: "Aurora cluster is encrypted but does not have a KMS key specified"
				});
			} else {
				results.checks.push({
					resourceName: cluster.DBClusterIdentifier,
					resourceArn: cluster.DBClusterArn,
					status: ComplianceStatus.PASS
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Aurora Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Aurora clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkAuroraEncryption(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Data at Rest is Encrypted",
	description:
		"Amazon Aurora allows you to encrypt your databases using keys you manage through AWS Key Management Service (KMS).",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_2.3",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkAuroraEncryption,
	serviceName: "Amazon Relational Database Service"
} satisfies RuntimeTest;
