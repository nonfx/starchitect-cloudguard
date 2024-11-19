package rules.dynamodb_table_deletion_protection

import data.fugue

__rego__metadoc__ := {
	"id": "DynamoDB.6",
	"title": "DynamoDB tables should have deletion protection enabled",
	"description": "This control checks if DynamoDB tables have deletion protection enabled to prevent accidental deletion and maintain business continuity.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_DynamoDB.6"]}, "severity": "Medium", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

# Get all DynamoDB tables
dynamodb_tables = fugue.resources("aws_dynamodb_table")

# Helper to check if deletion protection is enabled
is_deletion_protected(table) {
	table.deletion_protection_enabled == true
}

# Policy rule for DynamoDB tables
policy[p] {
	table := dynamodb_tables[_]
	is_deletion_protected(table)
	p = fugue.allow_resource(table)
}

policy[p] {
	table := dynamodb_tables[_]
	not is_deletion_protected(table)
	p = fugue.deny_resource_with_message(table, "DynamoDB table does not have deletion protection enabled")
}
