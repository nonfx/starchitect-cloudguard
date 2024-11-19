package rules.aws_keyspaces_encryption_at_rest_security

import data.fugue

__rego__metadoc__ := {
	"author": "ankit@nonfx.com",
	"id": "8.1.a",
	"title": "Ensure Keyspace Security is Configured - encryption at rest",
	"description": "In order to access Amazon Keyspaces the user is required to set specific networking parameters and security measurements without these extra steps they will not be able to access it. Users are required to create or select a virtual private cloud (VPC) and define their inbound and outbound rules accordingly.",
	"custom": {"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_8.1.a"]}},
}

resource_type := "MULTIPLE"

keyspaces = fugue.resources("aws_keyspaces_table")

encryption_at_rest_enabled(keyspace) {
	keyspace.encryption_specification[_].type == "AWS_OWNED_KMS_KEY"
}

encryption_at_rest_enabled(keyspace) {
	keyspace.encryption_specification[_].kms_key_identifier != null
}

policy[p] {
	keyspace := keyspaces[_]
	encryption_at_rest_enabled(keyspace)
	p = fugue.allow_resource(keyspace)
}

policy[p] {
	keyspace := keyspaces[_]
	not encryption_at_rest_enabled(keyspace)
	p = fugue.deny_resource_with_message(keyspace, "Amazon Keyspaces table does not have encryption at rest enabled with either AWS-owned KMS key or customer-managed KMS key")
}
