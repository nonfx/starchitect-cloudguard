package rules.aws_organizations_tag_policies_enabled

import data.fugue

__rego__metadoc__ := {
	"author": "rajat@nonfx.com",
	"id": "2.4",
	"title": "Ensure an Organizational EC2 Tag Policy has been Created",
	"description": "A tag policy enables you to define tag compliance rules to help you maintain consistency in the tags attached to your organization's resources",
	"custom": {
		"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.4"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

policies = fugue.resources("aws_organizations_policy")

tag_policy_exists(policy) {
	policy.type == "TAG_POLICY"
}

policy[p] {
	policy := policies[_]
	tag_policy_exists(policy)
	p = fugue.allow_resource(policy)
}

policy[p] {
	policy := policies[_]
	not tag_policy_exists(policy)
	p = fugue.deny_resource_with_message(policy, "No TAG_POLICY found in the organization. Ensure at least one tag policy is enabled.")
}
