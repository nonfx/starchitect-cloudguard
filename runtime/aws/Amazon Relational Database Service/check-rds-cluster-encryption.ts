import { RDSClient, DescribeDBClustersCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkRdsClusterEncryption(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all RDS clusters
		const response = await client.send(new DescribeDBClustersCommand({}));

		if (!response.DBClusters || response.DBClusters.length === 0) {
			results.checks = [
				{
					resourceName: "No RDS Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No RDS clusters found in the region"
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

			results.checks.push({
				resourceName: cluster.DBClusterIdentifier,
				resourceArn: cluster.DBClusterArn,
				status: cluster.StorageEncrypted ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: cluster.StorageEncrypted ? undefined : "RDS cluster is not encrypted at rest"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "RDS Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking RDS clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkRdsClusterEncryption(region);
	printSummary(generateSummary(results));
}

export default {
	title: "RDS DB clusters should be encrypted at rest",
	description:
		"RDS DB clusters must be encrypted at rest to protect data confidentiality and meet compliance requirements for data storage security.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.27",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsClusterEncryption
} satisfies RuntimeTest;
