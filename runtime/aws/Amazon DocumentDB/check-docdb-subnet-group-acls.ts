import { DocDBClient, DescribeDBSubnetGroupsCommand } from "@aws-sdk/client-docdb";
import { getAllDocDBClusters } from "../../utils/aws/get-all-docdb-clusters.js";
import { EC2Client, DescribeNetworkAclsCommand, DescribeSubnetsCommand } from "@aws-sdk/client-ec2";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkDocDBSubnetGroupAcls(region: string = "us-east-1"): Promise<ComplianceReport> {
	const docdbClient = new DocDBClient({ region });
	const ec2Client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all DocumentDB clusters using pagination
		const clusters = (await getAllDocDBClusters(docdbClient)) ?? [];

		if (clusters.length === 0) {
			results.checks.push({
				resourceName: "No DocumentDB Clusters",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No DocumentDB clusters found in the region"
			});
			return results;
		}

		for (const cluster of clusters) {
			if (!cluster.DBClusterIdentifier || !cluster.DBSubnetGroup) {
				results.checks.push({
					resourceName: cluster.DBClusterIdentifier || "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster missing identifier or subnet group"
				});
				continue;
			}

			try {
				// Get subnet group details
				const subnetGroup = await docdbClient.send(
					new DescribeDBSubnetGroupsCommand({
						DBSubnetGroupName: cluster.DBSubnetGroup
					})
				);

				if (!subnetGroup.DBSubnetGroups?.[0]?.Subnets?.length) {
					results.checks.push({
						resourceName: cluster.DBClusterIdentifier,
						status: ComplianceStatus.FAIL,
						message: "No subnets found in the subnet group"
					});
					continue;
				}

				const subnetIds = subnetGroup.DBSubnetGroups[0].Subnets.map(s => s.SubnetIdentifier).filter(
					Boolean
				) as string[];

				// Get subnet details
				const subnets = await ec2Client.send(
					new DescribeSubnetsCommand({
						SubnetIds: subnetIds
					})
				);

				// Get network ACLs
				// Get unique VPC IDs and ensure they are strings
				const vpcIds = [
					...new Set(
						subnets.Subnets?.map(s => s.VpcId).filter((id): id is string => id !== undefined)
					)
				];

				const networkAcls = await ec2Client.send(
					new DescribeNetworkAclsCommand({
						Filters:
							vpcIds.length > 0
								? [
										{
											Name: "vpc-id",
											Values: vpcIds
										}
									]
								: undefined
					})
				);

				const hasValidConfig = subnets.Subnets?.every(
					subnet =>
						subnet.VpcId && // Subnet is in VPC
						networkAcls.NetworkAcls?.some(acl =>
							acl.Associations?.some(assoc => assoc.SubnetId === subnet.SubnetId)
						) // Subnet has ACL association
				);

				results.checks.push({
					resourceName: cluster.DBClusterIdentifier,
					resourceArn: cluster.DBClusterArn,
					status: hasValidConfig ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: hasValidConfig
						? undefined
						: "One or more subnets are not properly configured with VPC and network ACLs"
				});
			} catch (error) {
				results.checks.push({
					resourceName: cluster.DBClusterIdentifier,
					resourceArn: cluster.DBClusterArn,
					status: ComplianceStatus.ERROR,
					message: `Error checking subnet configuration: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Region Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking DocumentDB clusters: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkDocDBSubnetGroupAcls(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure DocumentDB clusters are in VPCs with proper network ACLs",
	description:
		"This rule ensures that DocumentDB clusters are associated with subnets that are part of a VPC and have network ACLs configured. This helps in isolating DocumentDB instances within a secure Virtual Private Cloud (VPC) and controlling inbound and outbound traffic.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_7.1",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		},
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_7.2",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkDocDBSubnetGroupAcls,
	serviceName: "Amazon DocumentDB",
	shortServiceName: "docdb"
} satisfies RuntimeTest;
