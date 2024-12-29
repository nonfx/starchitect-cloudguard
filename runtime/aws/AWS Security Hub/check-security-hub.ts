import { SecurityHubClient, GetEnabledStandardsCommand } from "@aws-sdk/client-securityhub";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkSecurityHubEnabled(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new SecurityHubClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Check if Security Hub is enabled by retrieving enabled standards
		const command = new GetEnabledStandardsCommand({});
		const response = await client.send(command);

		// Check if any standards are enabled
		if (response.StandardsSubscriptions && response.StandardsSubscriptions.length > 0) {
			const standardArn = response.StandardsSubscriptions[0]?.StandardsArn;
			results.checks.push({
				resourceName: "SecurityHub",
				...(standardArn && { resourceArn: standardArn }),
				status: ComplianceStatus.PASS,
				message: "Security Hub is enabled"
			});
		} else {
			results.checks.push({
				resourceName: "SecurityHub",
				status: ComplianceStatus.FAIL,
				message: "Security Hub is not enabled in this region"
			});
		}
	} catch (error: any) {
		if (error.name === "ResourceNotFoundException") {
			results.checks.push({
				resourceName: "SecurityHub",
				status: ComplianceStatus.FAIL,
				message: "Security Hub is not enabled in this region"
			});
		} else {
			results.checks.push({
				resourceName: "SecurityHub",
				status: ComplianceStatus.ERROR,
				message: `Error checking Security Hub status: ${error instanceof Error ? error.message : String(error)}`
			});
		}
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkSecurityHubEnabled(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure AWS Security Hub is enabled",
	description:
		"Security Hub collects security data from across AWS accounts, services, and supported third-party partner products and helps you analyze your security trends and identify the highest priority security issues. When you enable Security Hub, it begins to consume, aggregate, organize, and prioritize findings from AWS services that you have enabled, such as Amazon GuardDuty, Amazon Inspector, and Amazon Macie. You can also enable integrations with AWS partner security products.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_4.16",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkSecurityHubEnabled
} satisfies RuntimeTest;
