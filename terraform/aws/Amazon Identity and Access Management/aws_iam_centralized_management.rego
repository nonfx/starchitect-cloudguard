package rules.aws_iam_centralized_management

import data.fugue

__rego__metadoc__ := {
	"id": "1.21",
	"title": "Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments",
	"description": "In multi-account environments, IAM user centralization facilitates greater user control. User access beyond the initial account is then provide via role assumption. Centralization of users can be accomplished through federation with an external identity provider or through the use of AWS Organizations.",
	"custom": {"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_1.21"]}, "severity": "Low", "author": "Starchitect Agent"},
}

# Policy evaluation
resource_type := "MULTIPLE"

# Get all IAM users
iam_users = fugue.resources("aws_iam_user")

# Get all SAML providers (indicating identity federation)
saml_providers = fugue.resources("aws_iam_saml_provider")

# Get AWS Organizations master account (indicating centralized account management)
organizations = fugue.resources("aws_organizations_organization")

# Check if there are any IAM users created directly in AWS accounts
direct_iam_users_exist {
	count(iam_users) > 0
}

# Check if SAML providers exist
saml_providers_exist {
	count(saml_providers) > 0
}

# Check if AWS Organizations exist
organizations_exist {
	count(organizations) > 0
}

policy[p] {
	user = iam_users[_]
	direct_iam_users_exist
	not saml_providers_exist
	not organizations_exist
	p = fugue.deny_resource(user)
}

policy[p] {
	user = iam_users[_]
	direct_iam_users_exist
	saml_providers_exist
	p = fugue.allow_resource(user)
}

policy[p] {
	user = iam_users[_]
	direct_iam_users_exist
	organizations_exist
	p = fugue.allow_resource(user)
}
