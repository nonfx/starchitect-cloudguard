package rules.iam_users_no_direct_policies

import data.fugue

__rego__metadoc__ := {
	"id": "IAM.2",
	"title": "IAM users should not have IAM policies attached",
	"description": "IAM users should not have direct policy attachments; instead, policies should be attached to groups or roles to reduce access management complexity and minimize the risk of excessive privileges.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_IAM.2"]}, "severity": "Medium"},
}

resource_type := "MULTIPLE"

# Get all IAM users and their policy attachments
iam_users = fugue.resources("aws_iam_user")

iam_user_policy_attachments = fugue.resources("aws_iam_user_policy_attachment")

iam_user_policies = fugue.resources("aws_iam_user_policy")

# Check if user has any direct policy attachments
has_direct_policies(user) {
	attachment := iam_user_policy_attachments[_]
	attachment.user == user.name
}

# Check if user has any inline policies
has_inline_policies(user) {
	policy := iam_user_policies[_]
	policy.user == user.name
}

policy[p] {
	user := iam_users[_]
	not has_direct_policies(user)
	not has_inline_policies(user)
	p = fugue.allow_resource(user)
}

policy[p] {
	user := iam_users[_]
	has_direct_policies(user)
	p = fugue.deny_resource_with_message(user, "IAM user has directly attached policies. Policies should be attached to groups instead.")
}

policy[p] {
	user := iam_users[_]
	has_inline_policies(user)
	p = fugue.deny_resource_with_message(user, "IAM user has inline policies. Policies should be attached to groups instead.")
}
