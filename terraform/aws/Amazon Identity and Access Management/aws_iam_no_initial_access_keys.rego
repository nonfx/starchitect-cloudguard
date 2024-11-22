package rules.no_initial_access_keys

__rego__metadoc__ := {
	"id": "1.11",
	"title": "Do not setup access keys during initial user setup for all IAM users that have a console password",
	"description": "AWS console defaults to no check boxes selected when creating a new IAM user. When creating the IAM User credentials you have to determine what type of access they require.",
	"custom": {"controls":{"CIS-AWS-Foundations-Benchmark_v3.0.0":["CIS-AWS-Foundations-Benchmark_v3.0.0_1.11"]},"severity":"Low","author":"Starchitect Agent"},
}

import data.fugue

resource_type := "MULTIPLE"

iam_users = fugue.resources("aws_iam_user")

iam_user_login_profiles = fugue.resources("aws_iam_user_login_profile")

iam_access_keys = fugue.resources("aws_iam_access_key")

# Helper function to check if a user has a login profile
has_login_profile(user) {
	profile = iam_user_login_profiles[_]
	profile.user == user.name
}

# Helper function to check if a user has an access key
has_access_key(user) {
	key = iam_access_keys[_]
	key.user == user.name
}

policy[p] {
	user = iam_users[_]
	has_login_profile(user)
	not has_access_key(user)
	p = fugue.allow_resource(user)
}

policy[p] {
	user = iam_users[_]
	has_login_profile(user)
	has_access_key(user)
	msg = sprintf("IAM user '%s' has both a console password and an access key. Access keys should not be set up during initial user creation for users with console access.", [user.name])
	p = fugue.deny_resource_with_message(user, msg)
}

# This rule focuses on users with console access, so we'll allow users without login profiles
policy[p] {
	user = iam_users[_]
	not has_login_profile(user)
	p = fugue.allow_resource(user)
}
