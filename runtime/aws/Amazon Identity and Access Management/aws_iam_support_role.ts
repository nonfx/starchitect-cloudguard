import { IAMClient, ListRolesCommand, ListAttachedRolePoliciesCommand } from "@aws-sdk/client-iam";

import { printSummary, generateSummary } from "~codegen/utils/stringUtils";

import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkIamSupportRole(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new IAMClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let roleFound = false;
		let marker: string | undefined;

		do {
			const listRolesResponse = await client.send(new ListRolesCommand({ Marker: marker }));

			if (!listRolesResponse.Roles || listRolesResponse.Roles.length === 0) {
				if (!roleFound) {
					results.checks = [
						{
							resourceName: "No IAM Roles",
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "No IAM roles found"
						}
					];
					return results;
				}
				break;
			}

			for (const role of listRolesResponse.Roles) {
				roleFound = true;
				if (!role.RoleName || !role.Arn) {
					results.checks.push({
						resourceName: "Unknown Role",
						status: ComplianceStatus.ERROR,
						message: "Role found without name or ARN"
					});
					continue;
				}

				try {
					const attachedPolicies = await client.send(
						new ListAttachedRolePoliciesCommand({
							RoleName: role.RoleName
						})
					);

					const hasSupportAccess = attachedPolicies.AttachedPolicies?.some(
						policy => policy.PolicyArn === "arn:aws:iam::aws:policy/AWSSupportAccess"
					);

					results.checks.push({
						resourceName: role.RoleName,
						resourceArn: role.Arn,
						status: hasSupportAccess ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: hasSupportAccess
							? undefined
							: "Role does not have AWSSupportAccess policy attached"
					});
				} catch (error) {
					results.checks.push({
						resourceName: role.RoleName,
						resourceArn: role.Arn,
						status: ComplianceStatus.ERROR,
						message: `Error checking role policies: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			}

			marker = listRolesResponse.Marker;
		} while (marker);

		// If no role has support access, add a failing check
		if (!results.checks.some(check => check.status === ComplianceStatus.PASS)) {
			results.checks.push({
				resourceName: "AWS Support Access",
				status: ComplianceStatus.FAIL,
				message: "No IAM role found with AWSSupportAccess policy attached"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "IAM Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking IAM roles: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkIamSupportRole(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure a support role has been created to manage incidents with AWS Support",
	description:
		"AWS provides a support center that can be used for incident notification and response, as well as technical support and customer services. Create an IAM Role to allow authorized users to manage incidents with AWS Support.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_1.17",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkIamSupportRole
} satisfies RuntimeTest;
