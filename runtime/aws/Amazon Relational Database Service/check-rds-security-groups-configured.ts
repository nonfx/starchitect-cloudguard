import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { EC2Client, DescribeSecurityGroupsCommand } from "@aws-sdk/client-ec2";
import { generateSummary, printSummary } from "../../utils/string-utils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

async function checkRdsSecurityGroupsConfigured(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const rdsClient = new RDSClient({ region });
	const ec2Client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all RDS instances
		const rdsResponse = await rdsClient.send(new DescribeDBInstancesCommand({}));

		if (!rdsResponse.DBInstances || rdsResponse.DBInstances.length === 0) {
			results.checks = [
				{
					resourceName: "No RDS Instances",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No RDS instances found in the region"
				}
			];
			return results;
		}

		for (const instance of rdsResponse.DBInstances) {
			if (!instance.DBInstanceIdentifier) {
				results.checks.push({
					resourceName: "Unknown RDS Instance",
					status: ComplianceStatus.ERROR,
					message: "RDS instance found without identifier"
				});
				continue;
			}

			const securityGroups = instance.VpcSecurityGroups || [];

			if (securityGroups.length === 0) {
				results.checks.push({
					resourceName: instance.DBInstanceIdentifier,
					resourceArn: instance.DBInstanceArn,
					status: ComplianceStatus.FAIL,
					message: "RDS instance does not have any security groups configured"
				});
				continue;
			}

			try {
				// Check each security group configuration
				let isValid = true;
				let invalidReason = "";

				for (const sg of securityGroups) {
					if (!sg.VpcSecurityGroupId) continue;

					const sgResponse = await ec2Client.send(
						new DescribeSecurityGroupsCommand({
							GroupIds: [sg.VpcSecurityGroupId]
						})
					);

					const securityGroup = sgResponse.SecurityGroups?.[0];
					if (!securityGroup) {
						isValid = false;
						invalidReason = `Security group ${sg.VpcSecurityGroupId} not found`;
						break;
					}

					// Check if security group has both ingress and egress rules
					if (!securityGroup.IpPermissions || securityGroup.IpPermissions.length === 0) {
						isValid = false;
						invalidReason = `Security group ${sg.VpcSecurityGroupId} has no inbound rules`;
						break;
					}

					if (
						!securityGroup.IpPermissionsEgress ||
						securityGroup.IpPermissionsEgress.length === 0
					) {
						isValid = false;
						invalidReason = `Security group ${sg.VpcSecurityGroupId} has no outbound rules`;
						break;
					}
				}

				results.checks.push({
					resourceName: instance.DBInstanceIdentifier,
					resourceArn: instance.DBInstanceArn,
					status: isValid ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isValid ? undefined : invalidReason
				});
			} catch (error) {
				results.checks.push({
					resourceName: instance.DBInstanceIdentifier,
					resourceArn: instance.DBInstanceArn,
					status: ComplianceStatus.ERROR,
					message: `Error checking security groups: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "RDS Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking RDS instances: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION;
	const results = await checkRdsSecurityGroupsConfigured(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure to Configure Security Groups for RDS Instances",
	description:
		"Configuring security groups benefits the user because it helps manage networks within the database and gives only certain permission for traffic that leaves and enters the database.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_3.4",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsSecurityGroupsConfigured
} satisfies RuntimeTest;
