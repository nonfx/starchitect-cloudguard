import { NeptuneClient } from "@aws-sdk/client-neptune";
import { getAllNeptuneClusters } from "../../utils/aws/get-all-neptune-clusters.js";
import { EC2Client, DescribeSecurityGroupsCommand } from "@aws-sdk/client-ec2";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkNeptuneNetworkSecurity(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const neptuneClient = new NeptuneClient({ region });
	const ec2Client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all Neptune clusters
		const clusters = await getAllNeptuneClusters(neptuneClient);

		if (clusters.length === 0) {
			results.checks = [
				{
					resourceName: "No Neptune Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Neptune clusters found in the region"
				}
			];
			return results;
		}

		// Check each cluster
		for (const cluster of clusters) {
			if (!cluster.DBClusterIdentifier) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without identifier"
				});
				continue;
			}

			try {
				// Check VPC and security group configuration
				if (!cluster.VpcSecurityGroups || cluster.VpcSecurityGroups.length === 0) {
					results.checks.push({
						resourceName: cluster.DBClusterIdentifier,
						resourceArn: cluster.DBClusterArn,
						status: ComplianceStatus.FAIL,
						message: "Neptune cluster is not configured with VPC security groups"
					});
					continue;
				}

				// Verify security group configurations
				const securityGroupIds = cluster.VpcSecurityGroups.map(sg => sg.VpcSecurityGroupId).filter(
					(id): id is string => id !== undefined
				);
				const securityGroups = await ec2Client.send(
					new DescribeSecurityGroupsCommand({
						GroupIds: securityGroupIds
					})
				);

				const hasValidSecurityGroups = securityGroups.SecurityGroups?.some(
					sg =>
						sg.IpPermissions &&
						sg.IpPermissions.length > 0 &&
						sg.IpPermissionsEgress &&
						sg.IpPermissionsEgress.length > 0
				);

				results.checks.push({
					resourceName: cluster.DBClusterIdentifier,
					resourceArn: cluster.DBClusterArn,
					status: hasValidSecurityGroups ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: hasValidSecurityGroups
						? undefined
						: "Neptune cluster security groups do not have proper inbound/outbound rules configured"
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
				resourceName: "Neptune Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Neptune clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

// Self-executing async function for the main entry point
if (import.meta.main) {
	(async () => {
		const region = process.env.AWS_REGION || "ap-southeast-1";
		const results = await checkNeptuneNetworkSecurity(region);
		printSummary(generateSummary(results));
	})().catch(console.error);
}

export default {
	serviceName: "Amazon Neptune",
	shortServiceName: "neptune",
	title: "Ensure Network Security is Enabled for AWS Neptune",
	description:
		"This helps ensure that all the necessary security measurements are taken to prevent a cyber-attack on AWS Neptune instances, such as utilizing VPC, creating certain inbound and outbound rules, and ACLs.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_9.1",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkNeptuneNetworkSecurity
} satisfies RuntimeTest;
