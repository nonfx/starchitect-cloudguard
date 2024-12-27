import { EC2Client, DescribeTransitGatewaysCommand } from "@aws-sdk/client-ec2";

import { printSummary, generateSummary } from "../../utils/string-utils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

async function checkTransitGatewayAutoAccept(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all transit gateways
		const command = new DescribeTransitGatewaysCommand({});
		const response = await client.send(command);

		if (!response.TransitGateways || response.TransitGateways.length === 0) {
			results.checks = [
				{
					resourceName: "No Transit Gateways",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Transit Gateways found in the region"
				}
			];
			return results;
		}

		// Check each transit gateway
		for (const tgw of response.TransitGateways) {
			if (!tgw.TransitGatewayId || !tgw.TransitGatewayArn) {
				results.checks.push({
					resourceName: "Unknown Transit Gateway",
					status: ComplianceStatus.ERROR,
					message: "Transit Gateway found without ID or ARN"
				});
				continue;
			}

			const isAutoAcceptEnabled = tgw.Options?.AutoAcceptSharedAttachments === "enable";

			results.checks.push({
				resourceName: tgw.TransitGatewayId,
				resourceArn: tgw.TransitGatewayArn,
				status: isAutoAcceptEnabled ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: isAutoAcceptEnabled
					? "Transit Gateway is configured to automatically accept VPC attachment requests"
					: undefined
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Transit Gateways: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkTransitGatewayAutoAccept(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Amazon EC2 Transit Gateways should not automatically accept VPC attachment requests",
	description:
		"This control checks if EC2 Transit Gateways are configured to automatically accept VPC attachment requests. The control fails if AutoAcceptSharedAttachments is enabled.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_EC2.23",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkTransitGatewayAutoAccept
} satisfies RuntimeTest;
