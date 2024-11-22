package rules.dynamodb_deletion_protection_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "DynamoDB.6",
	"title": "DynamoDB tables should have deletion protection enabled",
	"description": "DynamoDB tables must have deletion protection enabled to prevent accidental deletion and maintain business continuity.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_DynamoDB.6"]}, "severity": "Medium"},
}

resource_type := "MULTIPLE"

dynamodb_tables = fugue.resources("aws_dynamodb_table")

# Helper function to check if deletion protection is enabled
is_deletion_protected(table) {
	table.deletion_protection_enabled == true
}

# Policy rule for tables with deletion protection enabled
policy[p] {
	table := dynamodb_tables[_]
	is_deletion_protected(table)
	p = fugue.allow_resource(table)
}

# Policy rule for tables without deletion protection
policy[p] {
	table := dynamodb_tables[_]
	not is_deletion_protected(table)
	p = fugue.deny_resource_with_message(table, "DynamoDB table does not have deletion protection enabled")
}
