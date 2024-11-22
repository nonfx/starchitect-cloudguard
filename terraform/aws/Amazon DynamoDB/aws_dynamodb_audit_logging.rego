package rules.aws_dynamodb_audit_activity_cloudtrail

import data.fugue

__rego__metadoc__ := {
	"id": "4.7.b",
	"title": "Ensure Monitor and Audit Activity is enabled - Audit Logging",
	"description": "Regular monitoring and auditing of activity in Amazon DynamoDB help ensure your database's security, performance, and compliance.",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_4.7"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

cloudtrails := fugue.resources("aws_cloudtrail")

dynamodb_tables := fugue.resources("aws_dynamodb_table")

has_dynamodb_table_logging_enabled(trail) {
	trail.event_selector[_].data_resource[_].type == "AWS::DynamoDB::Table"
	trail.event_selector[_].include_management_events
}

policy[p] {
	table := dynamodb_tables[_]
	trail := cloudtrails[_]
	has_dynamodb_table_logging_enabled(trail)
	p = fugue.allow_resource(table)
}

policy[p] {
	table := dynamodb_tables[_]
	trail := cloudtrails[_]
	not has_dynamodb_table_logging_enabled(trail)
	msg := sprintf("DynamoDB table '%s' does not have audit logging enabled", [table.name])
	p = fugue.deny_resource_with_message(table, msg)
}

policy[p] {
	table := dynamodb_tables[_]
	count(cloudtrails) == 0
	msg := sprintf("DynamoDB table '%s' does not have audit logging configured using cloudtrail", [table.name])
	p = fugue.deny_resource_with_message(table, msg)
}
