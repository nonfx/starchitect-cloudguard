package rules.dynamodb_pitr_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "DynamoDB.2",
	"title": "DynamoDB tables should have point-in-time recovery enabled",
	"description": "This control checks whether point-in-time recovery (PITR) is enabled for DynamoDB tables. PITR provides continuous backups of your DynamoDB table data, allowing you to restore to any point in time within the last 35 days.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_DynamoDB.2"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

dynamodb_tables = fugue.resources("aws_dynamodb_table")

# Helper function to check if PITR is enabled
is_pitr_enabled(table) {
	table.point_in_time_recovery[_].enabled == true
}

policy[p] {
	table := dynamodb_tables[_]
	is_pitr_enabled(table)
	p = fugue.allow_resource(table)
}

policy[p] {
	table := dynamodb_tables[_]
	not is_pitr_enabled(table)
	p = fugue.deny_resource_with_message(table, "Point-in-time recovery (PITR) must be enabled for DynamoDB tables to ensure data recovery capabilities")
}
