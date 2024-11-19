package rules.aws_dynamodb_monitoring

import data.fugue

__rego__metadoc__ := {
	"author": "chandra@nonfx.com",
	"id": "4.7.a",
	"title": "Ensure Monitor and Audit Activity is enabled - Monitor",
	"description": "Regular monitoring and auditing of activity in Amazon DynamoDB help ensure your database's security, performance, and compliance.",
	"custom": {
		"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_4.7"]},
		"severity": "High",
	},
}

resource_type := "MULTIPLE"

dynamodb_tables := fugue.resources("aws_dynamodb_table")

cloudwatch_alarms := fugue.resources("aws_cloudwatch_metric_alarm")

dynamo_db_metrics := ["UserErrors", "SystemErrors", "ThrottledRequests", "ConsumedReadCapacityUnits", "ConsumedWriteCapacityUnits"]

is_valid_metric(metric_name) {
	dynamo_db_metrics[_] == metric_name
}

has_required_alarms(table) {
	alarm := cloudwatch_alarms[_]
	alarm.namespace == "AWS/DynamoDB"
	alarm.dimensions.TableName == table.name
	metric_name := alarm.metric_name
	is_valid_metric(metric_name)
}

policy[p] {
	table := dynamodb_tables[_]
	has_required_alarms(table)
	p = fugue.allow_resource(table)
}

policy[p] {
	table := dynamodb_tables[_]
	not has_required_alarms(table)
	msg := sprintf("DynamoDB table '%s' does not have adequate CloudWatch alarms set up.", [table.name])
	p = fugue.deny_resource_with_message(table, msg)
}
