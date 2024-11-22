package rules.aws_iam_support_role

import data.fugue

__rego__metadoc__ := {
	"id": "1.17",
	"title": "Ensure a support role has been created to manage incidents with AWS Support",
	"description": "AWS provides a support center that can be used for incident notification and response, as well as technical support and customer services. Create an IAM Role to allow authorized users to manage incidents with AWS Support.",
	"custom": {
		"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_1.17"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

# Policy evaluation
resource_type := "MULTIPLE"

iam_roles := fugue.resources("aws_iam_role")

# Define the AWS Support policy ARN
support_policy_arn := "arn:aws:iam::aws:policy/AWSSupportAccess"

# Get all IAM roles and their attached policies
support_role_associated_with_ipolicy(role_name) {
	policy_attachment = fugue.resources("aws_iam_role_policy_attachment")
	policy_attachment[_].role == role_name
	policy_attachment[_].policy_arn == support_policy_arn
}

# Check if any role has the support policy attached
support_role_exists {
	support_role_associated_with_ipolicy(iam_roles[_].name)
}

# Policy rules
policy[p] {
	support_role_exists
	p = fugue.allow_resource(iam_roles[_])
}

policy[p] {
	not support_role_exists
	p = fugue.deny_resource(iam_roles[_])
}
