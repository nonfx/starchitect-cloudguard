import {
	OrganizationsClient,
	ListPoliciesCommand,
	DescribePolicyCommand,
	type Policy,
	type PolicySummary
} from "@aws-sdk/client-organizations";

interface ListPoliciesResponse {
	Policies?: Array<{
		PolicySummary?: PolicySummary;
	}>;
}
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface TagPolicy {
	tags: {
		[key: string]: {
			tag_key: { assign: boolean };
			tag_value: { assign: boolean };
			operators_allowed_for_child_policies: string[];
			enforced_for: { assign: string[] };
		};
	};
}

const EC2_RESOURCE_TYPES = ["ec2:image", "ec2:instance", "ec2:reserved-instances"];

function isValidEc2TagPolicy(policyContent: TagPolicy): boolean {
	const tags = policyContent.tags;

	for (const tagKey in tags) {
		const tagValue = tags[tagKey];

		if (!tagValue) continue;

		const { tag_key, tag_value, operators_allowed_for_child_policies, enforced_for } = tagValue;

		if (
			tag_key?.assign &&
			tag_value?.assign &&
			operators_allowed_for_child_policies?.includes("ENFORCED_FOR") &&
			enforced_for?.assign
		) {
			const resources = enforced_for.assign;
			const matchingResources = resources.filter(res => EC2_RESOURCE_TYPES.includes(res));
			if (matchingResources.length === EC2_RESOURCE_TYPES.length) {
				return true;
			}
		}
	}

	return false;
}

async function checkTagPolicyCompliance(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new OrganizationsClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const listCommand = new ListPoliciesCommand({
			Filter: "TAG_POLICY"
		});

		const policies = (await client.send(listCommand)) as ListPoliciesResponse;

		if (!policies.Policies || policies.Policies.length === 0) {
			results.checks.push({
				resourceName: "Organizations",
				status: ComplianceStatus.FAIL,
				message: "No tag policies found in the organization"
			});
			return results;
		}

		let validPolicyFound = false;

		for (const policy of policies.Policies || []) {
			if (!policy.PolicySummary?.Id) continue;

			try {
				const describeCommand = new DescribePolicyCommand({
					PolicyId: policy.PolicySummary.Id
				});

				const policyDetails = await client.send(describeCommand);

				if (policyDetails.Policy?.Content) {
					try {
						const content = JSON.parse(policyDetails.Policy.Content) as TagPolicy;
						const isValid = isValidEc2TagPolicy(content);

						if (isValid) {
							validPolicyFound = true;
						}

						results.checks.push({
							resourceName: policy.PolicySummary.Name || "Unknown Policy",
							resourceArn: policy.PolicySummary.Arn,
							status: isValid ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
							message: isValid
								? undefined
								: "Tag policy does not enforce required EC2 resource types"
						});
					} catch (jsonError) {
						results.checks.push({
							resourceName: policy.PolicySummary.Name || "Unknown Policy",
							resourceArn: policy.PolicySummary.Arn,
							status: ComplianceStatus.ERROR,
							message: `Error checking policy: Invalid JSON content - ${jsonError instanceof Error ? jsonError.message : String(jsonError)}`
						});
					}
				}
			} catch (policyError) {
				results.checks.push({
					resourceName: policy.PolicySummary.Name || "Unknown Policy",
					resourceArn: policy.PolicySummary.Arn,
					status: ComplianceStatus.ERROR,
					message: `Error checking policy: ${policyError instanceof Error ? policyError.message : String(policyError)}`
				});
			}
		}

		if (!validPolicyFound) {
			results.checks.push({
				resourceName: "Organizations",
				status: ComplianceStatus.FAIL,
				message: "No valid EC2 tag policy found that enforces all required resource types"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Organizations",
			status: ComplianceStatus.ERROR,
			message: `Error checking tag policies: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkTagPolicyCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Tag Policies are Enabled",
	description:
		"Tag policies help you standardize tags on all tagged resources across your organization.",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.3",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkTagPolicyCompliance,
	serviceName: "AWS Organizations",
	shortServiceName: "organizations"
} satisfies RuntimeTest;
