import { EFSClient, DescribeAccessPointsCommand } from "@aws-sdk/client-efs";

import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkEfsAccessPointUserIdentity(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new EFSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const command = new DescribeAccessPointsCommand({});
		const response = await client.send(command);

		if (!response.AccessPoints || response.AccessPoints.length === 0) {
			results.checks = [
				{
					resourceName: "No EFS Access Points",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No EFS access points found in the region"
				}
			];
			return results;
		}

		for (const accessPoint of response.AccessPoints) {
			if (!accessPoint.AccessPointArn) {
				results.checks.push({
					resourceName: "Unknown Access Point",
					status: ComplianceStatus.ERROR,
					message: "Access point found without ARN"
				});
				continue;
			}

			const hasValidPosixUser =
				accessPoint.PosixUser &&
				accessPoint.PosixUser.Uid !== undefined &&
				accessPoint.PosixUser.Gid !== undefined;

			results.checks.push({
				resourceName: accessPoint.AccessPointId || "Unknown ID",
				resourceArn: accessPoint.AccessPointArn,
				status: hasValidPosixUser ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasValidPosixUser
					? undefined
					: "EFS access point does not have a valid POSIX user identity configured"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking EFS access points: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkEfsAccessPointUserIdentity(region);
	printSummary(generateSummary(results));
}

export default {
	title: "EFS access points should enforce a user identity",
	description:
		"EFS access points must enforce user identity by defining POSIX user identity during creation for secure application access management.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_EFS.4",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkEfsAccessPointUserIdentity
} satisfies RuntimeTest;
