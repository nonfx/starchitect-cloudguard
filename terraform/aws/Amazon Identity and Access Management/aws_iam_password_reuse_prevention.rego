package rules.password_reuse_prevention

__rego__metadoc__ := {
	"id": "1.9",
	"title": "Ensure IAM password policy prevents password reuse",
	"description": "IAM password policies can prevent the reuse of a given password by the same user. It is recommended that the password policy prevent the reuse of passwords.",
	"custom": {"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_1.9"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

import data.fugue

resource_type := "MULTIPLE"

password_reuse_prevention_threshold = 24

aws_iam_account_password_policies = fugue.resources("aws_iam_account_password_policy")

policy[p] {
	password_policy = aws_iam_account_password_policies[_]

	password_policy.password_reuse_prevention >= password_reuse_prevention_threshold

	p = fugue.allow_resource(password_policy)
}
