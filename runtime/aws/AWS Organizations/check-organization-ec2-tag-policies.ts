import {
	OrganizationsClient,
	ListPoliciesCommand,
	PolicyType
} from "@aws-sdk/client-organizations";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkOrganizationTagPolicies(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new OrganizationsClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const command = new ListPoliciesCommand({
			Filter: PolicyType.TAG_POLICY
		});

		const response = await client.send(command);

		if (!response.Policies || response.Policies.length === 0) {
			results.checks.push({
				resourceName: "Organization Tag Policies",
				status: ComplianceStatus.FAIL,
				message:
					"No TAG_POLICY found in the organization. Ensure at least one tag policy is enabled."
			});
			return results;
		}

		// Check each tag policy
		for (const policy of response.Policies) {
			results.checks.push({
				resourceName: policy.Name || "Unknown Policy",
				resourceArn: policy.Arn,
				status: ComplianceStatus.PASS,
				message: undefined
			});
		}
	} catch (error) {
		if (error instanceof Error && error.name === "AWSOrganizationsNotInUseException") {
			results.checks.push({
				resourceName: "AWS Organizations",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "AWS Organizations is not enabled for this account"
			});
		} else {
			results.checks.push({
				resourceName: "Organization Tag Policies",
				status: ComplianceStatus.ERROR,
				message: `Error checking organization tag policies: ${error instanceof Error ? error.message : String(error)}`
			});
		}
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkOrganizationTagPolicies(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure an Organizational EC2 Tag Policy has been Created",
	description:
		"A tag policy enables you to define tag compliance rules to help you maintain consistency in the tags attached to your organization's resources",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.4",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkOrganizationTagPolicies,
	serviceName: "AWS Organizations",
	shortServiceName: "organizations"
} satisfies RuntimeTest;
