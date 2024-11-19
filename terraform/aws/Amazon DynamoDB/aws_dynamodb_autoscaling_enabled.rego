package rules.dynamodb_autoscaling_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "DynamoDB.1",
	"title": "DynamoDB tables should automatically scale capacity with demand",
	"description": "DynamoDB tables must implement automatic capacity scaling through on-demand mode or provisioned mode with auto-scaling to prevent throttling and maintain availability.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_DynamoDB.1"]}, "severity": "Medium", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

# Get all DynamoDB tables
dynamodb_tables = fugue.resources("aws_dynamodb_table")

# Get all autoscaling targets
autoscaling_targets = fugue.resources("aws_appautoscaling_target")

# Helper function to check if table uses on-demand capacity
is_on_demand(table) {
	table.billing_mode == "PAY_PER_REQUEST"
}

# Helper function to check if table has autoscaling targets
has_autoscaling_targets(table_name) {
	target := autoscaling_targets[_]
	contains(target.resource_id, table_name)
	target.service_namespace == "dynamodb"
}

# Policy rule for allowing tables with on-demand capacity
policy[p] {
	table := dynamodb_tables[_]
	is_on_demand(table)
	p = fugue.allow_resource(table)
}

# Policy rule for allowing tables with autoscaling targets
policy[p] {
	table := dynamodb_tables[_]
	table.billing_mode == "PROVISIONED"
	has_autoscaling_targets(table.name)
	p = fugue.allow_resource(table)
}

# Policy rule for denying tables without proper capacity configuration
policy[p] {
	table := dynamodb_tables[_]
	not is_on_demand(table)
	not has_autoscaling_targets(table.name)
	p = fugue.deny_resource_with_message(
		table,
		"DynamoDB table must use on-demand capacity mode or have autoscaling targets configured",
	)
}
