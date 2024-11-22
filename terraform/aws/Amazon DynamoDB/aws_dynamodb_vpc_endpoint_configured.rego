package rules.aws_dynamodb_vpc_endpoint_configured

import data.fugue

__rego__metadoc__ := {
	"id": "4.5",
	"title": "Ensure VPC Endpoints are configured for DynamoDB",
	"description": "Using VPC endpoints with Amazon DynamoDB allows you to securely access DynamoDB resources within your Amazon Virtual Private Cloud (VPC). This keeps your traffic off the public internet.",
	"custom": {
		"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_4.5"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

vpc_endpoints = fugue.resources("aws_vpc_endpoint")

dynamodb_tables = fugue.resources("aws_dynamodb_table")

dynamodb_endpoint_exists {
	endpoint := vpc_endpoints[_]
	contains(endpoint.service_name, "dynamodb")
}

policy[p] {
	dynamodb_endpoint_exists
	table := dynamodb_tables[_]
	p = fugue.allow_resource(table)
}

policy[p] {
	not dynamodb_endpoint_exists
	table := dynamodb_tables[_]
	p = fugue.deny_resource_with_message(table, "No VPC endpoint for DynamoDB is configured. Configure a VPC endpoint to securely access DynamoDB within your VPC.")
}
