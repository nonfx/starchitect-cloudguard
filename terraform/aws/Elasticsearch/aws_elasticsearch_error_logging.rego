package rules.elasticsearch_error_logging

import data.fugue

__rego__metadoc__ := {
	"id": "ES.4",
	"title": "Elasticsearch domain error logging to CloudWatch Logs should be enabled",
	"description": "This rule ensures that Elasticsearch domains have error logging enabled and configured to send logs to CloudWatch Logs for security auditing and issue diagnosis.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_ES.4"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

resources = fugue.resources("aws_elasticsearch_domain")

valid_log_types := {
	"INDEX_SLOW_LOGS",
	"SEARCH_SLOW_LOGS",
	"ES_APPLICATION_LOGS",
	"AUDIT_LOGS",
}

has_valid_logging(resource) {
	log_options = resource.log_publishing_options[_]
	log_options.enabled == true
	valid_log_types[log_options.log_type]
	log_options.cloudwatch_log_group_arn != null
}

policy[p] {
	resource = resources[_]
	has_valid_logging(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = resources[_]
	not has_valid_logging(resource)
	p = fugue.deny_resource_with_message(
		resource,
		"Elasticsearch domain must have error logging enabled and configured to send logs to CloudWatch Logs",
	)
}
