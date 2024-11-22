package rules.aws_iam_account_password_policy

__rego__metadoc__ := {
	"id": "1.8",
	"title": "Ensure IAM password policy requires minimum length of 14 or greater",
	"description": "Password policies are, in part, used to enforce password complexity requirements. IAM password policies can be used to ensure password are at least a given length. It is recommended that the password policy require a minimum password length 14.",
	"custom": {"controls":{"CIS-AWS-Foundations-Benchmark_v3.0.0":["CIS-AWS-Foundations-Benchmark_v3.0.0_1.8"]},"severity":"Low","author":"Starchitect Agent"},
}

import data.fugue

resource_type := "MULTIPLE"

password_policies = fugue.resources("aws_iam_account_password_policy")

has_minimum_password_length(resource) {
	_ = resource.minimum_password_length
}

policy[r] {
	password_policy = password_policies[_]
	has_minimum_password_length(password_policy)
	password_policy.minimum_password_length >= 14
	r = fugue.allow_resource(password_policy)
}

policy[r] {
	password_policy = password_policies[_]
	not has_minimum_password_length(password_policy)
	msg = "Password policy does not have minimum_password_length property. It must be at least 14 characters."
	r = fugue.deny_resource_with_message(password_policy, msg)
}

policy[r] {
	password_policy = password_policies[_]
	has_minimum_password_length(password_policy)
	not password_policy.minimum_password_length >= 14
	msg = "Password policy is too short. It must be at least 14 characters."
	r = fugue.deny_resource_with_message(password_policy, msg)
}
