package rules.aws_keyspaces_vpc_endpoint_security_authentication

import data.fugue

__rego__metadoc__ := {
	"id": "8.1",
	"title": "Ensure Keyspace Security is Configured - authentication",
	"description": "In order to access Amazon Keyspaces the user is required to set specific networking parameters and security measurements without these extra steps they will not be able to access it. Users are required to create or select a virtual private cloud (VPC) and define their inbound and outbound rules accordingly",
	"custom": {
		"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_8.1"]},
		"severity": "High",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

keyspaces := fugue.resources("aws_keyspaces_keyspace")

iam_roles := fugue.resources("aws_iam_role")

iam_role_policies := fugue.resources("aws_iam_role_policy")

has_iam_policy_for_keyspaces(roles, policies) {
	role := roles[_]
	policy := policies[_]
	policy.role == role.id
	contains(policy.policy, "cassandra.amazonaws.com")
}

policy[p] {
	count(keyspaces) > 0
	keyspace := keyspaces[_]
	has_iam_policy_for_keyspaces(iam_roles, iam_role_policies)
	p = fugue.allow_resource(keyspace)
}

policy[p] {
	count(keyspaces) > 0
	keyspace := keyspaces[_]
	not has_iam_policy_for_keyspaces(iam_roles, iam_role_policies)
	msg := sprintf("Keyspace '%s' does not have the correct IAM role policy for secure access.", [keyspace.name])
	p = fugue.deny_resource_with_message(keyspace, msg)
}
