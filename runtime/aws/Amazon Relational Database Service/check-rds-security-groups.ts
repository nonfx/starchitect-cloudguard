import {
	RDSClient,
	DescribeDBClustersCommand,
	DescribeDBInstancesCommand
} from "@aws-sdk/client-rds";
import { EC2Client, DescribeSecurityGroupsCommand } from "@aws-sdk/client-ec2";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkRdsSecurityGroups(region: string = "us-east-1"): Promise<ComplianceReport> {
	const rdsClient = new RDSClient({ region });
	const ec2Client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all RDS clusters
		const clusters = await rdsClient.send(new DescribeDBClustersCommand({}));
		const instances = await rdsClient.send(new DescribeDBInstancesCommand({}));

		if (
			(!clusters.DBClusters || clusters.DBClusters.length === 0) &&
			(!instances.DBInstances || instances.DBInstances.length === 0)
		) {
			results.checks.push({
				resourceName: "No RDS Resources",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No RDS clusters or instances found in the region"
			});
			return results;
		}

		// Check clusters
		if (clusters.DBClusters) {
			for (const cluster of clusters.DBClusters) {
				if (!cluster.DBClusterIdentifier) continue;

				const securityGroups = cluster.VpcSecurityGroups || [];

				if (securityGroups.length === 0) {
					results.checks.push({
						resourceName: cluster.DBClusterIdentifier,
						resourceArn: cluster.DBClusterArn,
						status: ComplianceStatus.FAIL,
						message: "RDS cluster has no security groups attached"
					});
					continue;
				}

				// Check each security group
				for (const sg of securityGroups) {
					if (!sg.VpcSecurityGroupId) continue;

					try {
						const sgDetails = await ec2Client.send(
							new DescribeSecurityGroupsCommand({
								GroupIds: [sg.VpcSecurityGroupId]
							})
						);

						const securityGroup = sgDetails.SecurityGroups?.[0];
						if (!securityGroup) continue;

						const hasInboundRules =
							securityGroup.IpPermissions && securityGroup.IpPermissions.length > 0;
						const hasOutboundRules =
							securityGroup.IpPermissionsEgress && securityGroup.IpPermissionsEgress.length > 0;

						if (!hasInboundRules || !hasOutboundRules) {
							results.checks.push({
								resourceName: cluster.DBClusterIdentifier,
								resourceArn: cluster.DBClusterArn,
								status: ComplianceStatus.FAIL,
								message: `Security group ${sg.VpcSecurityGroupId} has missing ${!hasInboundRules ? "inbound" : "outbound"} rules`
							});
						} else {
							results.checks.push({
								resourceName: cluster.DBClusterIdentifier,
								resourceArn: cluster.DBClusterArn,
								status: ComplianceStatus.PASS,
								message: undefined
							});
						}
					} catch (error) {
						results.checks.push({
							resourceName: cluster.DBClusterIdentifier,
							resourceArn: cluster.DBClusterArn,
							status: ComplianceStatus.ERROR,
							message: `Error checking security group: ${error instanceof Error ? error.message : String(error)}`
						});
					}
				}
			}
		}

		// Check instances
		if (instances.DBInstances) {
			for (const instance of instances.DBInstances) {
				if (!instance.DBInstanceIdentifier) continue;

				const securityGroups = instance.VpcSecurityGroups || [];

				if (securityGroups.length === 0) {
					results.checks.push({
						resourceName: instance.DBInstanceIdentifier,
						resourceArn: instance.DBInstanceArn,
						status: ComplianceStatus.FAIL,
						message: "RDS instance has no security groups attached"
					});
					continue;
				}

				// Check each security group
				for (const sg of securityGroups) {
					if (!sg.VpcSecurityGroupId) continue;

					try {
						const sgDetails = await ec2Client.send(
							new DescribeSecurityGroupsCommand({
								GroupIds: [sg.VpcSecurityGroupId]
							})
						);

						const securityGroup = sgDetails.SecurityGroups?.[0];
						if (!securityGroup) continue;

						const hasInboundRules =
							securityGroup.IpPermissions && securityGroup.IpPermissions.length > 0;
						const hasOutboundRules =
							securityGroup.IpPermissionsEgress && securityGroup.IpPermissionsEgress.length > 0;

						if (!hasInboundRules || !hasOutboundRules) {
							results.checks.push({
								resourceName: instance.DBInstanceIdentifier,
								resourceArn: instance.DBInstanceArn,
								status: ComplianceStatus.FAIL,
								message: `Security group ${sg.VpcSecurityGroupId} has missing ${!hasInboundRules ? "inbound" : "outbound"} rules`
							});
						} else {
							results.checks.push({
								resourceName: instance.DBInstanceIdentifier,
								resourceArn: instance.DBInstanceArn,
								status: ComplianceStatus.PASS,
								message: undefined
							});
						}
					} catch (error) {
						results.checks.push({
							resourceName: instance.DBInstanceIdentifier,
							resourceArn: instance.DBInstanceArn,
							status: ComplianceStatus.ERROR,
							message: `Error checking security group: ${error instanceof Error ? error.message : String(error)}`
						});
					}
				}
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "RDS Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking RDS resources: ${error instanceof Error ? error.message : String(error)}`
		});
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkRdsSecurityGroups(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure the Use of Security Groups",
	description:
		"Security groups act as a firewall for associated Amazon RDS DB instances, controlling both inbound and outbound traffic",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_2.2",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsSecurityGroups
} satisfies RuntimeTest;
