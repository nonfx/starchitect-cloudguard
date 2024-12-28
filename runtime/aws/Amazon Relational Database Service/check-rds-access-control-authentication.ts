import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkRdsAccessControlAuthentication(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
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
			if (!instance.DBInstanceIdentifier) {
				results.checks.push({
					resourceName: "Unknown Instance",
					status: ComplianceStatus.ERROR,
					message: "RDS instance found without identifier"
				});
				continue;
			}

			const isCompliant =
				instance.PubliclyAccessible === false && instance.IAMDatabaseAuthenticationEnabled === true;

			results.checks.push({
				resourceName: instance.DBInstanceIdentifier,
				resourceArn: instance.DBInstanceArn,
				status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isCompliant
					? undefined
					: `RDS instance has improper access control configuration: ${instance.PubliclyAccessible ? "publicly accessible" : ""} ${!instance.IAMDatabaseAuthenticationEnabled ? "IAM authentication disabled" : ""}`
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

if (import.meta.main) {
	const region = process.env.AWS_REGION || "ap-southeast-1";
	const results = await checkRdsAccessControlAuthentication(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure to Implement Access Control and Authentication",
	description:
		"Users should select whether they like to enable authentication. If they want to authenticate a password would be required, which would only allow the authorized person to access the database. Defining access control allows specific workers in a business access to the database",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_3.7",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsAccessControlAuthentication
} satisfies RuntimeTest;
