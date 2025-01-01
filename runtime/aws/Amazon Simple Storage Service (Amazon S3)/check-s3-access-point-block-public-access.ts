import {
	GetAccessPointCommand,
	ListAccessPointsCommand,
	S3Control
} from "@aws-sdk/client-s3-control";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkS3AccessPointBlockPublicAccess(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const stsClient = new STSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get account ID
		const callerIdentity = await stsClient.send(new GetCallerIdentityCommand({}));
		const accountId = callerIdentity.Account;
		if (!accountId) {
			throw new Error("Failed to get AWS account ID");
		}

		const s3Control = new S3Control({ region });

		// List all access points
		const listResponse = await s3Control.send(
			new ListAccessPointsCommand({
				AccountId: accountId
			})
		);

		if (!listResponse.AccessPointList || listResponse.AccessPointList.length === 0) {
			results.checks = [
				{
					resourceName: "No Access Points",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No S3 access points found in the account"
				}
			];
			return results;
		}

		// Check each access point
		for (const accessPoint of listResponse.AccessPointList) {
			if (!accessPoint.Name) {
				results.checks.push({
					resourceName: "Unknown Access Point",
					status: ComplianceStatus.ERROR,
					message: "Access point found without name"
				});
				continue;
			}

			try {
				const accessPointResponse = await s3Control.send(
					new GetAccessPointCommand({
						AccountId: accountId,
						Name: accessPoint.Name
					})
				);

				// Check if all block public access settings are enabled
				const blockConfig = accessPointResponse.PublicAccessBlockConfiguration;
				if (!blockConfig) {
					results.checks.push({
						resourceName: accessPoint.Name,
						resourceArn: accessPoint.AccessPointArn,
						status: ComplianceStatus.FAIL,
						message: "No public access block configuration found for access point"
					});
					continue;
				}

				const isFullyBlocked =
					blockConfig.BlockPublicAcls &&
					blockConfig.BlockPublicPolicy &&
					blockConfig.IgnorePublicAcls &&
					blockConfig.RestrictPublicBuckets;

				results.checks.push({
					resourceName: accessPoint.Name,
					resourceArn: accessPoint.AccessPointArn,
					status: isFullyBlocked ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isFullyBlocked
						? undefined
						: "Access point does not have all public access block settings enabled"
				});
			} catch (error) {
				results.checks.push({
					resourceName: accessPoint.Name,
					resourceArn: accessPoint.AccessPointArn,
					status: ComplianceStatus.ERROR,
					message: `Error checking access point: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Account Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking S3 access points: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkS3AccessPointBlockPublicAccess(region);
	printSummary(generateSummary(results));
}

export default {
	title: "S3 access points should have block public access settings enabled",
	description:
		"S3 access points must have block public access settings enabled to prevent unauthorized access and maintain security. All block public access settings should be enabled by default for new access points and cannot be changed after creation.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_S3.19",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkS3AccessPointBlockPublicAccess,
	serviceName: "Amazon Simple Storage Service (Amazon S3)",
	shortServiceName: "s3"
} satisfies RuntimeTest;
