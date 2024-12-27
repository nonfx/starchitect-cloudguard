import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

async function checkRdsEncryptionAtRest(region: string = "us-east-1"): Promise<ComplianceReport> {
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

				results.checks.push({
					resourceName: instance.DBInstanceIdentifier,
					resourceArn: instance.DBInstanceArn,
					status: instance.StorageEncrypted ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: instance.StorageEncrypted
						? undefined
						: "RDS instance does not have encryption-at-rest enabled"
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
	const results = await checkRdsEncryptionAtRest(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure that encryption-at-rest is enabled for RDS Instances",
	description:
		"Amazon RDS encrypted DB instances use the industry standard AES-256 encryption algorithm to encrypt your data on the server that hosts your Amazon RDS DB instances. After your data is encrypted, Amazon RDS handles authentication of access and decryption of your data transparently with a minimal impact on performance.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_2.3.1",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		},
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_3.5",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsEncryptionAtRest
} satisfies RuntimeTest;
