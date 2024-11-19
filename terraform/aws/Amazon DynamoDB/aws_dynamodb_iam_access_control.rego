# Package declaration for the rule
package rules.aws_dynamodb_iam_access_control

# Import the fugue library
import data.fugue

__rego__metadoc__ := {
	"author": "sachin@nonfx.com",
	"id": "4.1",
	"title": "AWS Identity and Access Management (IAM) lets you securely control your users' access to AWS services and resources. To manage access control for Amazon DynamoDB, you can create IAM policies that control access to tables and data",
	"custom": {"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_4.1"]}, "severity": "High", "reviewer": "ssghait.007@gmail.com"},
}

# Set resource type to MULTIPLE for advanced rule
resource_type := "MULTIPLE"

# Query for all DynamoDB tables and resource policies
dynamodb_tables = fugue.resources("aws_dynamodb_table")

dynamodb_policies = fugue.resources("aws_dynamodb_resource_policy")

# Auxiliary function to check if IAM policy is attached
has_iam_policy(table) {
	policy := dynamodb_policies[_]
	contains(policy.resource_arn, table.id)
}

# Policy rule that holds the set of judgements
policy[p] {
	table := dynamodb_tables[_]
	has_iam_policy(table)
	p = fugue.allow_resource(table)
}

policy[p] {
	table := dynamodb_tables[_]
	not has_iam_policy(table)
	p = fugue.deny_resource_with_message(table, "DynamoDB table should have an IAM resource policy attached.")
}
