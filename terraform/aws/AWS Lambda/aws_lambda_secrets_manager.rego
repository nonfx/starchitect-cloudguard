package rules.aws_lambda_secrets_manager

import data.fugue
import future.keywords.every

__rego__metadoc__ := {
	"id": "4.3",
	"title": "Ensure AWS Secrets manager is configured and being used by Lambda for databases",
	"description": "Lambda functions often have to access a database or other services within your environment.",
	"custom": {"severity":"Medium","controls":{"CIS-AWS-Compute-Services-Benchmark_v1.0.0":["CIS-AWS-Compute-Services-Benchmark_v1.0.0_4.3"]},"author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

lambda_functions := fugue.resources("aws_lambda_function")

resource_has_property_environment(resource) {
	_ = resource.environment
}

resource_has_property_variables(resource) {
	_ = resource.variables
}

resource_has_keys(resource) {
	value = resource[_]
	value
}

using_secrets_manager(function) {
	not resource_has_property_environment(function)
}

using_secrets_manager(function) {
	resource_has_property_environment(function)
	not resource_has_property_variables(function.environment[0])
}

using_secrets_manager(function) {
	resource_has_property_environment(function)
	resource_has_property_variables(function.environment[0])
	env_vars := function.environment[0].variables
	not resource_has_keys(env_vars)
}

using_secrets_manager(function) {
	resource_has_property_environment(function)
	resource_has_property_variables(function.environment[0])
	env_vars := function.environment[0].variables
	resource_has_keys(env_vars)

	# val := env_vars[key]
	every key, val in env_vars {
		is_db_credential(key, val)
		regex.match(`aws_secretsmanager_secret`, val)
	}
}

is_db_credential(key, val) {
	not contains(key, "DB_")
}

is_db_credential(key, val) {
	contains(key, "PASSWORD")
	contains(val, "aws_secretsmanager_secret")
}

is_db_credential(key, val) {
	contains(key, "SECRET")
	contains(val, "aws_secretsmanager_secret")
}

policy[p] {
	function := lambda_functions[_]
	using_secrets_manager(function)
	p = fugue.allow_resource(function)
}

policy[p] {
	function := lambda_functions[_]
	not using_secrets_manager(function)
	msg := sprintf("Lambda function '%s' is not configured to use AWS Secrets Manager for database credentials.", [function])
	p = fugue.deny_resource_with_message(function, msg)
}
