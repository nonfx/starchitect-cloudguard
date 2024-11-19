package rules.aws_iam_users_permissions_through_group

import data.fugue

__rego__metadoc__ := {
	"author": "sachin@nonfx.com",
	"id": "1.15",
	"title": "Ensure IAM Users Receive Permissions Only Through Groups",
	"description": "IAM users should be granted permissions only through groups. Directly attached policies or inline policies should be avoided.",
	"custom": {
		"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_1.15"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

iam_users := fugue.resources("aws_iam_user")

inline_policies := fugue.resources("aws_iam_user_policy")

attached_policies := fugue.resources("aws_iam_user_policy_attachment")

group_memberships := fugue.resources("aws_iam_group_membership")

# Check if a user has inline policies
user_has_inline_policies(user) {
	inline_policies[_].user == user.name
}

# Check if a user has attached policies
user_has_attached_policies(user) {
	attached_policies[_].user == user.name
}

# Check if a user is part of any IAM groups
user_in_groups(user) {
	group_memberships[_].users[_] == user.name
}

# Check if the user meets the requirement of receiving permissions only through groups
user_valid(user) {
	user_in_groups(user)
	not user_has_inline_policies(user)
	not user_has_attached_policies(user)
}

policy[p] {
	user := iam_users[_]
	user_valid(user)
	p := fugue.allow_resource(user)
}

policy[p] {
	user := iam_users[_]
	not user_valid(user)
	p := fugue.deny_resource(user)
}
