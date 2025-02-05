import { IAMClient, GetAccountPasswordPolicyCommand } from "@aws-sdk/client-iam";

import { printSummary, generateSummary } from "../../utils/string-utils.js";

import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkPasswordPolicyLength(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new IAMClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get password policy
		const command = new GetAccountPasswordPolicyCommand({});
		const response = await client.send(command);

		if (!response.PasswordPolicy) {
			results.checks.push({
				resourceName: "Password Policy",
				status: ComplianceStatus.FAIL,
				message: "No password policy is configured"
			});
			return results;
		}

		const minLength = response.PasswordPolicy.MinimumPasswordLength || 0;

		results.checks.push({
			resourceName: "Password Policy",
			status: minLength >= 14 ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
			message:
				minLength >= 14
					? undefined
					: `Password policy minimum length is ${minLength}, which is less than the required 14 characters`
		});
	} catch (error) {
		if (error instanceof Error && error.name === "NoSuchEntityException") {
			results.checks.push({
				resourceName: "Password Policy",
				status: ComplianceStatus.FAIL,
				message: "No password policy is configured"
			});
		} else {
			results.checks.push({
				resourceName: "Password Policy",
				status: ComplianceStatus.ERROR,
				message: `Error checking password policy: ${error instanceof Error ? error.message : String(error)}`
			});
		}
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkPasswordPolicyLength(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure IAM password policy requires minimum length of 14 or greater",
	description:
		"Password policies are, in part, used to enforce password complexity requirements. IAM password policies can be used to ensure password are at least a given length. It is recommended that the password policy require a minimum password length 14.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_1.8",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkPasswordPolicyLength,
	serviceName: "Amazon Identity and Access Management",
	shortServiceName: "iam"
} satisfies RuntimeTest;
