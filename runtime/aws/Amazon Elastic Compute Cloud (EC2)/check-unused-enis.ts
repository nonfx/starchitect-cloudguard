import { EC2Client, DescribeNetworkInterfacesCommand } from "@aws-sdk/client-ec2";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkUnusedENIs(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const command = new DescribeNetworkInterfacesCommand({});
		const response = await client.send(command);

		if (!response.NetworkInterfaces || response.NetworkInterfaces.length === 0) {
			results.checks.push({
				resourceName: "No ENIs",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No ENIs found in the region"
			});
			return results;
		}

		for (const eni of response.NetworkInterfaces) {
			if (!eni.NetworkInterfaceId) {
				results.checks.push({
					resourceName: "Unknown ENI",
					status: ComplianceStatus.ERROR,
					message: "ENI found without ID"
				});
				continue;
			}

			const isAttached = eni.Attachment !== undefined;

			results.checks.push({
				resourceName: eni.NetworkInterfaceId,
				status: isAttached ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isAttached ? undefined : "ENI is not attached to any instance"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "ENI Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking ENIs: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION;
	const results = await checkUnusedENIs(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure unused ENIs are removed (Manual)",
	description:
		"Identify and delete any unused Amazon AWS Elastic Network Interfaces in order to adhere to best practices and to avoid reaching the service limit. An AWS Elastic Network Interface (ENI) is pronounced unused when is not attached anymore to an EC2 instance.",
	controls: [
		{
			id: "AWS-Operational-Best-Practices_v1.0.0_ENI.1",
			document: "AWS-Operational-Best-Practices_v1.0.0"
		}
	],
	severity: "LOW",
	execute: checkUnusedENIs
} satisfies RuntimeTest;
