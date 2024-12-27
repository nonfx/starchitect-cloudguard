import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

// List of engines that support IAM authentication
const SUPPORTED_ENGINES = [
	"mysql",
	"postgres",
	"aurora",
	"aurora-mysql",
	"aurora-postgresql",
	"mariadb"
];

async function checkRdsIamAuthCompliance(region: string = "us-east-1"): Promise<ComplianceReport> {
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

				if (!instance.Engine) {
					results.checks.push({
						resourceName: instanceId,
						status: ComplianceStatus.ERROR,
						message: "Instance engine information not available"
					});
					continue;
				}

				// Check if engine supports IAM authentication
				if (!SUPPORTED_ENGINES.includes(instance.Engine.toLowerCase())) {
					results.checks.push({
						resourceName: instanceId,
						resourceArn: instance.DBInstanceArn,
						status: ComplianceStatus.NOTAPPLICABLE,
						message: `Engine ${instance.Engine} does not support IAM authentication`
					});
					continue;
				}

				// Check IAM authentication status
				results.checks.push({
					resourceName: instanceId,
					resourceArn: instance.DBInstanceArn,
					status: instance.IAMDatabaseAuthenticationEnabled
						? ComplianceStatus.PASS
						: ComplianceStatus.FAIL,
					message: instance.IAMDatabaseAuthenticationEnabled
						? undefined
						: "IAM database authentication is not enabled"
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
	const results = await checkRdsIamAuthCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "IAM authentication should be configured for RDS instances",
	description:
		"RDS instances must have IAM database authentication enabled for secure, token-based access instead of passwords.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.10",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsIamAuthCompliance
} satisfies RuntimeTest;
