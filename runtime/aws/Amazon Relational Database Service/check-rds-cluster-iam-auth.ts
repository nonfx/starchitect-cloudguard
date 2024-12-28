import { RDSClient, DescribeDBClustersCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkRdsClusterIamAuth(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all RDS clusters
		const command = new DescribeDBClustersCommand({});
		const response = await client.send(command);

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

		// Check each cluster for IAM authentication
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
				status: cluster.IAMDatabaseAuthenticationEnabled
					? ComplianceStatus.PASS
					: ComplianceStatus.FAIL,
				message: cluster.IAMDatabaseAuthenticationEnabled
					? undefined
					: "IAM authentication is not enabled for this RDS cluster"
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
	const results = await checkRdsClusterIamAuth(region);
	printSummary(generateSummary(results));
}

export default {
	title: "IAM authentication should be configured for RDS clusters",
	description:
		"IAM authentication should be enabled for RDS clusters to allow password-free, token-based authentication with SSL encryption.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.12",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsClusterIamAuth
} satisfies RuntimeTest;
