import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

const DEFAULT_USERNAMES = ["admin", "postgres", "root"];

async function checkRdsCustomAdminUsername(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let marker: string | undefined;
		let instanceFound = false;

		do {
			const command = new DescribeDBInstancesCommand({
				Marker: marker
			});

			const response = await client.send(command);

			if (!response.DBInstances || response.DBInstances.length === 0) {
				if (!instanceFound) {
					results.checks = [
						{
							resourceName: "No RDS Instances",
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "No RDS instances found in the region"
						}
					];
					return results;
				}
				break;
			}

			for (const instance of response.DBInstances) {
				instanceFound = true;

				if (!instance.DBInstanceIdentifier || !instance.DBInstanceArn) {
					results.checks.push({
						resourceName: "Unknown Instance",
						status: ComplianceStatus.ERROR,
						message: "RDS instance found without identifier or ARN"
					});
					continue;
				}

				if (!instance.MasterUsername) {
					results.checks.push({
						resourceName: instance.DBInstanceIdentifier,
						resourceArn: instance.DBInstanceArn,
						status: ComplianceStatus.ERROR,
						message: "Unable to determine master username"
					});
					continue;
				}

				const usesDefaultUsername = DEFAULT_USERNAMES.includes(instance.MasterUsername);

				results.checks.push({
					resourceName: instance.DBInstanceIdentifier,
					resourceArn: instance.DBInstanceArn,
					status: usesDefaultUsername ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
					message: usesDefaultUsername
						? `RDS instance uses default admin username '${instance.MasterUsername}'. Use a custom administrator username.`
						: undefined
				});
			}

			marker = response.Marker;
		} while (marker);
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
	const region = process.env.AWS_REGION;
	const results = await checkRdsCustomAdminUsername(region);
	printSummary(generateSummary(results));
}

export default {
	title: "RDS database instances should use a custom administrator username",
	description:
		"RDS database instances must use custom administrator usernames instead of default values to enhance security and prevent unauthorized access.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.25",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsCustomAdminUsername,
	serviceName: "Amazon Relational Database Service"
} satisfies RuntimeTest;
