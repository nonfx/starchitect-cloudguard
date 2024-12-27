import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

async function checkRdsPublicAccess(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all RDS instances
		const response = await client.send(new DescribeDBInstancesCommand({}));

		if (!response.DBInstances || response.DBInstances.length === 0) {
			results.checks = [
				{
					resourceName: "No RDS Instances",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No RDS instances found in the region"
				}
			];
			return results;
		}

		// Check each RDS instance
		for (const instance of response.DBInstances) {
			if (!instance.DBInstanceIdentifier || !instance.DBInstanceArn) {
				results.checks.push({
					resourceName: "Unknown Instance",
					status: ComplianceStatus.ERROR,
					message: "RDS instance found without identifier or ARN"
				});
				continue;
			}

			const isPublic = instance.PubliclyAccessible === true;

			results.checks.push({
				resourceName: instance.DBInstanceIdentifier,
				resourceArn: instance.DBInstanceArn,
				status: isPublic ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: isPublic ? "RDS instance is publicly accessible" : undefined
			});
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
	const results = await checkRdsPublicAccess(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure that public access is not given to RDS Instance",
	description:
		"Ensure and verify that RDS database instances provisioned in your AWS account do restrict unauthorized access in order to minimize security risks. To restrict access to any publicly accessible RDS database instance, you must disable the database Publicly Accessible flag and update the VPC security group associated with the instance.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_2.3.3",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsPublicAccess
} satisfies RuntimeTest;
