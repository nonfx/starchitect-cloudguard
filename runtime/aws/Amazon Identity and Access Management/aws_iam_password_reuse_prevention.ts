import { IAMClient, GetAccountPasswordPolicyCommand } from "@aws-sdk/client-iam";

import { printSummary, generateSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkPasswordReusePreventionCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
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

		// Check password reuse prevention setting
		const preventionNumber = response.PasswordPolicy.PasswordReusePrevention || 0;
		const requiredPreventionNumber = 24; // As per CIS benchmark

		results.checks.push({
			resourceName: "Password Policy",
			status:
				preventionNumber >= requiredPreventionNumber
					? ComplianceStatus.PASS
					: ComplianceStatus.FAIL,
			message:
				preventionNumber >= requiredPreventionNumber
					? undefined
					: `Password reuse prevention is set to ${preventionNumber}, but should be at least ${requiredPreventionNumber}`
		});
	} catch (error: any) {
		if (error.name === "NoSuchEntityException") {
			results.checks.push({
				resourceName: "Password Policy",
				status: ComplianceStatus.FAIL,
				message: "No password policy is configured"
			});
		} else {
			results.checks.push({
				resourceName: "Password Policy",
				status: ComplianceStatus.ERROR,
				message: `Error checking password policy: ${error.message}`
			});
		}
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkPasswordReusePreventionCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure IAM password policy prevents password reuse",
	description:
		"IAM password policies can prevent the reuse of a given password by the same user. It is recommended that the password policy prevent the reuse of passwords.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_1.9",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkPasswordReusePreventionCompliance
} satisfies RuntimeTest;
