package rules.aws_dynamodb_stream

import data.fugue

__rego__metadoc__ := {
	"author": "chandra@nonfx.com",
	"id": "4.6",
	"title": "Ensure DynamoDB Streams and AWS Lambda for Automated Compliance Checking is Enabled",
	"description": "Enabling DynamoDB Streams and integrating AWS Lambda allows you to automate compliance checking and perform actions based on changes made to your DynamoDB data.",
	"custom": {
		"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_4.6"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

dynamodb_tables := fugue.resources("aws_dynamodb_table")

lambda_event_source_mappings := fugue.resources("aws_lambda_event_source_mapping")

stream_enabled(table) {
	table.stream_enabled
}

# Function to check if there is a corresponding Lambda function for the DynamoDB stream
lambda_for_dynamodb_stream_exists(table) {
	some i
	mapping := lambda_event_source_mappings[i]
	contains(mapping.event_source_arn, "aws_dynamodb_table")
}

policy[p] {
	table := dynamodb_tables[_]
	not stream_enabled(table)
	msg := sprintf("DynamoDB table '%s' does not have stream enabled.", [table.name])
	p := fugue.deny_resource_with_message(table, msg)
}

# Policy to deny DynamoDB table if stream is enabled but no corresponding Lambda exists
policy[p] {
	table := dynamodb_tables[_]
	not lambda_for_dynamodb_stream_exists(table)
	msg := sprintf("DynamoDB table '%s' has stream enabled but no corresponding Lambda function exists", [table.name])
	p = fugue.deny_resource_with_message(table, msg)
}

policy[p] {
	table := dynamodb_tables[_]
	stream_enabled(table)
	lambda_for_dynamodb_stream_exists(table)
	p := fugue.allow_resource(table)
}
