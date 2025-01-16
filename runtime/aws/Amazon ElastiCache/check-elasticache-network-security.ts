import { ElastiCacheClient, type CacheCluster } from "@aws-sdk/client-elasticache";
import { getCacheClusters } from "../../utils/aws/elasticache-utils.js";
import {
	EC2Client,
	DescribeSecurityGroupsCommand,
	DescribeNetworkAclsCommand
} from "@aws-sdk/client-ec2";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkElastiCacheNetworkSecurity(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const elasticacheClient = new ElastiCacheClient({ region });
	const ec2Client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all ElastiCache clusters using utility function
		const cacheClusters = await getCacheClusters(elasticacheClient);

		if (cacheClusters.length === 0) {
			results.checks.push({
				resourceName: "No ElastiCache Clusters",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No ElastiCache clusters found in the region"
			});
			return results;
		}

		for (const cluster of cacheClusters) {
			if (!cluster.CacheClusterId) continue;

			try {
				// Check if cluster is in VPC
				const isInVpc = cluster.CacheSubnetGroupName !== undefined;

				if (!isInVpc) {
					results.checks.push({
						resourceName: cluster.CacheClusterId,
						resourceArn: cluster.ARN,
						status: ComplianceStatus.FAIL,
						message: "ElastiCache cluster is not in a VPC"
					});
					continue;
				}

				// Check security groups
				if (!cluster.SecurityGroups || cluster.SecurityGroups.length === 0) {
					results.checks.push({
						resourceName: cluster.CacheClusterId,
						resourceArn: cluster.ARN,
						status: ComplianceStatus.FAIL,
						message: "No security groups attached to the cluster"
					});
					continue;
				}

				let securityGroupsCompliant = true;
				for (const sg of cluster.SecurityGroups) {
					if (!sg.SecurityGroupId) continue;

					const sgDetails = await ec2Client.send(
						new DescribeSecurityGroupsCommand({
							GroupIds: [sg.SecurityGroupId]
						})
					);

					const securityGroup = sgDetails.SecurityGroups?.[0];
					if (
						!securityGroup ||
						!securityGroup.IpPermissions?.length ||
						!securityGroup.IpPermissionsEgress?.length
					) {
						securityGroupsCompliant = false;
						break;
					}
				}

				if (!securityGroupsCompliant) {
					results.checks.push({
						resourceName: cluster.CacheClusterId,
						resourceArn: cluster.ARN,
						status: ComplianceStatus.FAIL,
						message: "Security groups do not have proper ingress/egress rules"
					});
					continue;
				}

				// If all checks pass
				results.checks.push({
					resourceName: cluster.CacheClusterId,
					resourceArn: cluster.ARN,
					status: ComplianceStatus.PASS,
					message: undefined
				});
			} catch (error) {
				results.checks.push({
					resourceName: cluster.CacheClusterId,
					resourceArn: cluster.ARN,
					status: ComplianceStatus.ERROR,
					message: `Error checking cluster security: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "ElastiCache Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking ElastiCache clusters: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkElastiCacheNetworkSecurity(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Network Security is Enabled",
	description:
		"Implementing network security for Amazon ElastiCache involves configuring your Virtual Private Cloud (VPC), security groups, and network access controls to control access to your ElastiCache clusters.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_5.2",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkElastiCacheNetworkSecurity,
	serviceName: "Amazon ElastiCache",
	shortServiceName: "elasticache"
} satisfies RuntimeTest;
