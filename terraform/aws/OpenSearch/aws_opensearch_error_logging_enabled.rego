package rules.opensearch_error_logging

import data.fugue

__rego__metadoc__ := {
	"id": "Opensearch.4",
	"title": "OpenSearch domain error logging to CloudWatch Logs should be enabled",
	"description": "OpenSearch domains must enable error logging to CloudWatch Logs for security monitoring and compliance tracking.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Opensearch.4"]}, "severity": "Medium", "author": "llmagent", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

opensearch_domains = fugue.resources("aws_opensearch_domain")

# Define valid log types
valid_log_types = {
	"INDEX_SLOW_LOGS",
	"SEARCH_SLOW_LOGS",
	"ES_APPLICATION_LOGS",
	"AUDIT_LOGS",
}

# Check if any valid log type is properly configured
has_valid_logging(domain) {
	log_config := domain.log_publishing_options[_]
	log_config.enabled == true
	valid_log_types[log_config.log_type]
	log_config.cloudwatch_log_group_arn != null
}

policy[p] {
	domain := opensearch_domains[_]
	has_valid_logging(domain)
	p = fugue.allow_resource(domain)
}

policy[p] {
	domain := opensearch_domains[_]
	not has_valid_logging(domain)
	p = fugue.deny_resource_with_message(
		domain,
		"OpenSearch domain must have at least one of the following log types enabled and configured to send logs to CloudWatch Logs: INDEX_SLOW_LOGS, SEARCH_SLOW_LOGS, ES_APPLICATION_LOGS, AUDIT_LOGS",
	)
}
