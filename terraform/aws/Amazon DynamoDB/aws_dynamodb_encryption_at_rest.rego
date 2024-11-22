package rules.aws_dynamodb_encryption_at_rest

import data.fugue

__rego__metadoc__ := {
	"id": "4.3",
	"title": "Ensure DynamoDB Encryption at Rest",
	"description": "Encryption at rest in Amazon DynamoDB enhances the security of your data by encrypting it using AWS Key Management Service (AWS KMS) keys.",
	"custom": {
		"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_4.3"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

dynamodb_tables = fugue.resources("aws_dynamodb_table")

encryption_at_rest_enabled(table) {
	table.server_side_encryption[_].enabled == true
}

policy[p] {
	table := dynamodb_tables[_]
	encryption_at_rest_enabled(table)
	p = fugue.allow_resource(table)
}

policy[p] {
	table := dynamodb_tables[_]
	not encryption_at_rest_enabled(table)
	p = fugue.deny_resource_with_message(table, "DynamoDB table does not have encryption at rest enabled")
}
