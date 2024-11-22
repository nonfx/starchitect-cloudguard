package rules.aws_keyspaces_encryption_at_rest

import data.fugue

__rego__metadoc__ := {
	"id": "8.3",
	"title": "Ensure Data at Rest and in Transit is Encrypted - at rest",
	"description": "Once a user is logged in to their AWS account and has access to their Amazon Keyspaces they are encouraged to choose from the following two options to encrypt their data. Depending on which key they select for encryption at rest would store the data according to their preference. For encryption in transit the user is also encouraged to choose from two options depending on if the data needs to be encrypted during transit.",
	"custom": {"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_8.3"]}, "author": "Starchitect Agent"},
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
