import { IAMClient, ListUsersCommand, ListSAMLProvidersCommand } from "@aws-sdk/client-iam";
import { OrganizationsClient, DescribeOrganizationCommand } from "@aws-sdk/client-organizations";

import { printSummary, generateSummary } from "../../utils/string-utils.js";

import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkIamCentralizedManagement(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const iamClient = new IAMClient({ region });
	const orgClient = new OrganizationsClient({ region });

	const results: ComplianceReport = {
		checks: []
	};

	try {
		const usersResponse = await iamClient.send(new ListUsersCommand({}));
		const hasIamUsers = (usersResponse.Users?.length ?? 0) > 0;

		if (!hasIamUsers) {
			results.checks.push({
				resourceName: "IAM Users",
				status: ComplianceStatus.ERROR,
				message: "No IAM users found in the account"
			});
			return results;
		}

		const samlResponse = await iamClient.send(new ListSAMLProvidersCommand({}));
		const hasSamlProviders = (samlResponse.SAMLProviderList?.length ?? 0) > 0;

		let hasOrganization = false;
		try {
			await orgClient.send(new DescribeOrganizationCommand({}));
			hasOrganization = true;
		} catch (error: any) {
			if (error.name !== "AccessDeniedException") {
				throw error;
			}
		}

		const isCentralized = hasSamlProviders || hasOrganization;

		results.checks.push({
			resourceName: "IAM User Management",
			status: isCentralized ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
			message: isCentralized
				? `IAM users are managed centrally via ${hasSamlProviders ? "SAML federation" : "AWS Organizations"}`
				: "IAM users are not managed centrally through federation or AWS Organizations"
		});
	} catch (error) {
		results.checks.push({
			resourceName: "IAM Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking IAM centralization: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkIamCentralizedManagement(region);
	printSummary(generateSummary(results));
}

export default {
	title:
		"Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments",
	description:
		"In multi-account environments, IAM user centralization facilitates greater user control. User access beyond the initial account is then provide via role assumption. Centralization of users can be accomplished through federation with an external identity provider or through the use of AWS Organizations.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_1.21",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkIamCentralizedManagement
} satisfies RuntimeTest;
