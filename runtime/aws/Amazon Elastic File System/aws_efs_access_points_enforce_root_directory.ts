import { EFSClient, DescribeAccessPointsCommand } from "@aws-sdk/client-efs";

import { printSummary, generateSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkEfsAccessPointsRootDirectory(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new EFSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let nextToken: string | undefined;
		let accessPointFound = false;

		do {
			const command = new DescribeAccessPointsCommand({
				NextToken: nextToken
			});

			const response = await client.send(command);

			if (!response.AccessPoints || response.AccessPoints.length === 0) {
				if (!accessPointFound) {
					results.checks = [
						{
							resourceName: "No EFS Access Points",
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "No EFS access points found in the region"
						}
					];
					return results;
				}
				break;
			}

			for (const accessPoint of response.AccessPoints) {
				accessPointFound = true;

				if (!accessPoint.AccessPointArn) {
					results.checks.push({
						resourceName: "Unknown Access Point",
						status: ComplianceStatus.ERROR,
						message: "Access point found without ARN"
					});
					continue;
				}

				const rootDirectory = accessPoint.RootDirectory?.Path;
				const isCompliant = rootDirectory && rootDirectory !== "/";

				results.checks.push({
					resourceName: accessPoint.AccessPointId || "Unknown ID",
					resourceArn: accessPoint.AccessPointArn,
					status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isCompliant
						? undefined
						: 'EFS access point does not enforce a root directory or uses root path "/"'
				});
			}

			nextToken = response.NextToken;
		} while (nextToken);
	} catch (error) {
		results.checks = [
			{
				resourceName: "EFS Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking EFS access points: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkEfsAccessPointsRootDirectory(region);
	printSummary(generateSummary(results));
}

export default {
	title: "EFS access points should enforce a root directory",
	description:
		"EFS access points must enforce a root directory to restrict data access by ensuring users can only access specified subdirectory files.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_EFS.3",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkEfsAccessPointsRootDirectory
} satisfies RuntimeTest;
