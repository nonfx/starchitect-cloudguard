import {
	ConfigServiceClient,
	GetResourceConfigHistoryCommand
} from "@aws-sdk/client-config-service";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkSecurityHubEnabled(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new ConfigServiceClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Check Security Hub configuration through AWS Config
		const response = await client.send(
			new GetResourceConfigHistoryCommand({
				//@ts-expect-error @todo - to be fixed, temporary fix for CLI unblock
				resourceType: "AWS::SecurityHub::Hub",
				resourceId: "default",
				limit: 1
			})
		);

		if (response.configurationItems && response.configurationItems.length > 0) {
			const config = response.configurationItems[0];
			//@ts-expect-error @todo - to be fixed, temporary fix for CLI unblock
			if (config.configurationStateId === "Active") {
				results.checks.push({
					resourceName: "SecurityHub",
					//@ts-expect-error @todo - to be fixed, temporary fix for CLI unblock
					resourceArn: config.arn,
					status: ComplianceStatus.PASS,
					message: "Security Hub is enabled"
				});
			} else {
				results.checks.push({
					resourceName: "SecurityHub",
					status: ComplianceStatus.FAIL,
					message: "Security Hub is disabled"
				});
			}
		} else {
			results.checks.push({
				resourceName: "SecurityHub",
				status: ComplianceStatus.FAIL,
				message: "Security Hub is not configured in this region"
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
