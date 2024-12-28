import {
	RDSClient,
	DescribeDBInstancesCommand,
	DescribeDBSubnetGroupsCommand
} from "@aws-sdk/client-rds";
import { EC2Client, DescribeVpcsCommand } from "@aws-sdk/client-ec2";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkRdsInVpcCompliance(region: string = "us-east-1"): Promise<ComplianceReport> {
	const rdsClient = new RDSClient({ region });
	const ec2Client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Check if any VPCs exist
		const vpcsResponse = await ec2Client.send(new DescribeVpcsCommand({}));
		const vpcExists = vpcsResponse.Vpcs && vpcsResponse.Vpcs.length > 0;

		if (!vpcExists) {
			results.checks.push({
				resourceName: "VPC Check",
				status: ComplianceStatus.FAIL,
				message: "No VPC exists. Create a VPC before deploying RDS instances."
			});
			return results;
		}

		// Get all RDS instances
		const rdsResponse = await rdsClient.send(new DescribeDBInstancesCommand({}));

		if (!rdsResponse.DBInstances || rdsResponse.DBInstances.length === 0) {
			results.checks.push({
				resourceName: "RDS Instances",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No RDS instances found in the region"
			});
			return results;
		}

		// Check each RDS instance
		for (const instance of rdsResponse.DBInstances) {
			if (!instance.DBInstanceIdentifier) {
				results.checks.push({
					resourceName: "Unknown Instance",
					status: ComplianceStatus.ERROR,
					message: "RDS instance found without identifier"
				});
				continue;
			}

			const instanceId = instance.DBInstanceIdentifier;

			if (!instance.DBSubnetGroup) {
				results.checks.push({
					resourceName: instanceId,
					resourceArn: instance.DBInstanceArn,
					status: ComplianceStatus.FAIL,
					message: "RDS instance is not deployed in a VPC (no subnet group)"
				});
				continue;
			}

			try {
				// Verify subnet group details
				const subnetGroupResponse = await rdsClient.send(
					new DescribeDBSubnetGroupsCommand({
						DBSubnetGroupName: instance.DBSubnetGroup.DBSubnetGroupName
					})
				);

				const subnetGroup = subnetGroupResponse.DBSubnetGroups?.[0];

				if (!subnetGroup || !subnetGroup.Subnets || subnetGroup.Subnets.length === 0) {
					results.checks.push({
						resourceName: instanceId,
						resourceArn: instance.DBInstanceArn,
						status: ComplianceStatus.FAIL,
						message: "RDS instance subnet group has no associated subnets"
					});
					continue;
				}

				results.checks.push({
					resourceName: instanceId,
					resourceArn: instance.DBInstanceArn,
					status: ComplianceStatus.PASS,
					message: undefined
				});
			} catch (error) {
				results.checks.push({
					resourceName: instanceId,
					resourceArn: instance.DBInstanceArn,
					status: ComplianceStatus.ERROR,
					message: `Error checking subnet group: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "RDS Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking RDS instances: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkRdsInVpcCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure RDS instances are deployed in a VPC",
	description:
		"RDS instances should be deployed within a VPC to enhance security and network isolation. This rule checks if RDS instances are associated with a VPC subnet group and if the VPC exists.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_3.3",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsInVpcCompliance
} satisfies RuntimeTest;
