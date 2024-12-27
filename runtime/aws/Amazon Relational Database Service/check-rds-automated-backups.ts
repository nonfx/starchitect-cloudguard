import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

async function checkRdsAutomatedBackups(region: string = "us-east-1"): Promise<ComplianceReport> {
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
				const instanceId = instance.DBInstanceIdentifier || "Unknown Instance";

				// Skip read replicas as they inherit backup settings from source
				if (instance.ReadReplicaSourceDBInstanceIdentifier) {
					results.checks.push({
						resourceName: instanceId,
						resourceArn: instance.DBInstanceArn,
						status: ComplianceStatus.NOTAPPLICABLE,
						message: "Instance is a read replica"
					});
					continue;
				}

				const hasValidBackups =
					instance.BackupRetentionPeriod !== undefined && instance.BackupRetentionPeriod >= 7;

				results.checks.push({
					resourceName: instanceId,
					resourceArn: instance.DBInstanceArn,
					status: hasValidBackups ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: hasValidBackups
						? undefined
						: `Automated backups not enabled or retention period (${instance.BackupRetentionPeriod} days) is less than required 7 days`
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

if (require.main === module) {
	const region = process.env.AWS_REGION;
	const results = await checkRdsAutomatedBackups(region);
	printSummary(generateSummary(results));
}

export default {
	title: "RDS instances should have automatic backups enabled",
	description:
		"RDS instances must have automated backups enabled with a minimum retention period of 7 days for data recovery and system resilience.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.11",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsAutomatedBackups
} satisfies RuntimeTest;
