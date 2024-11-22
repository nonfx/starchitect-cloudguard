package rules.aws_organizations_ec2_tag_policy

import data.fugue
import future.keywords.in

__rego__metadoc__ := {
	"id": "2.3",
	"title": "Ensure Tag Policies are Enabled",
	"description": "Tag policies help you standardize tags on all tagged resources across your organization.",
	"custom": {
		"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.3"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

policies = fugue.resources("aws_organizations_policy")

ec2_resource_types := ["ec2:image", "ec2:instance", "ec2:reserved-instances"]

valid_ec2_tag_policy(policy) {
	policy.type == "TAG_POLICY"
	content := json.unmarshal(policy.content)
	tags := content.tags
	some tag_key
	tag_value := tags[tag_key]
	tag_value.tag_key.assign
	tag_value.tag_value.assign
	enforce := tag_value.operators_allowed_for_child_policies
	"ENFORCED_FOR" in enforce
	resources := tag_value.enforced_for.assign
	count([res | res := resources[_]; res in ec2_resource_types]) == 3
}

ec2_tag_policy_exists {
	some policy in policies
	valid_ec2_tag_policy(policy)
}

policy[p] {
	ec2_tag_policy_exists
	p = fugue.allow_resource(policies[_])
}

policy[p] {
	not ec2_tag_policy_exists
	p = fugue.deny_resource_with_message(policies[_], "No valid EC2 tag policy found in the organization. Ensure an EC2 tag policy is created that enforces tags for ec2:image, ec2:instance, and ec2:reserved-instances.")
}
