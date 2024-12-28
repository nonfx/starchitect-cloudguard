import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkRdsAutoMinorVersionUpgrade(
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
			try {
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

					results.checks.push({
						resourceName: instance.DBInstanceIdentifier,
						resourceArn: instance.DBInstanceArn,
						status: instance.AutoMinorVersionUpgrade
							? ComplianceStatus.PASS
							: ComplianceStatus.FAIL,
						message: instance.AutoMinorVersionUpgrade
							? undefined
							: "Auto Minor Version Upgrade is not enabled for this RDS instance"
					});
				}

				marker = response.Marker;
			} catch (error) {
				results.checks.push({
					resourceName: "RDS Instances List",
					status: ComplianceStatus.ERROR,
					message: `Error listing RDS instances: ${error instanceof Error ? error.message : String(error)}`
				});
				break;
			}
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
	const results = await checkRdsAutoMinorVersionUpgrade(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Auto Minor Version Upgrade feature is Enabled for RDS Instances",
	description:
		"Ensure that RDS database instances have the Auto Minor Version Upgrade flag enabled in order to receive automatically minor engine upgrades during the specified maintenance window. So, RDS instances can get the new features, bug fixes, and security patches for their database engines.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_2.3.2",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsAutoMinorVersionUpgrade
} satisfies RuntimeTest;
