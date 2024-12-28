import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkRdsInstancesInVpc(region: string = "us-east-1"): Promise<ComplianceReport> {
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

				if (!instance.DBInstanceArn) {
					results.checks.push({
						resourceName: instanceId,
						status: ComplianceStatus.ERROR,
						message: "Instance ARN not found"
					});
					continue;
				}

				const isInVpc =
					instance.DBSubnetGroup ||
					(instance.VpcSecurityGroups && instance.VpcSecurityGroups.length > 0);

				results.checks.push({
					resourceName: instanceId,
					resourceArn: instance.DBInstanceArn,
					status: isInVpc ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isInVpc ? undefined : "RDS instance is not deployed in a VPC"
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
	const results = await checkRdsInstancesInVpc(region);
	printSummary(generateSummary(results));
}

export default {
	title: "RDS instances should be deployed in a VPC",
	description:
		"This control checks whether RDS instances are deployed in a VPC. The control fails if an RDS instance is not deployed in a VPC.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.18",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsInstancesInVpc
} satisfies RuntimeTest;
