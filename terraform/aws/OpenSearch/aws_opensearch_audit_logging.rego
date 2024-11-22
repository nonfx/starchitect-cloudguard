package rules.opensearch_audit_logging

import data.fugue

__rego__metadoc__ := {
	"id": "OpenSearch.5",
	"title": "OpenSearch domains should have audit logging enabled",
	"description": "OpenSearch domains must enable audit logging to track user activity and maintain security compliance through CloudWatch Logs.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_OpenSearch.5"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all OpenSearch domains
domains = fugue.resources("aws_opensearch_domain")

# Helper to check if audit logging is properly configured
has_valid_audit_logging(domain) {
	log_config := domain.log_publishing_options[_]
	log_config.log_type == "AUDIT_LOGS"
	log_config.enabled == true
	log_config.cloudwatch_log_group_arn != null
}

# Allow if domain has valid audit logging
policy[p] {
	domain := domains[_]
	has_valid_audit_logging(domain)
	p = fugue.allow_resource(domain)
}

# Deny if domain is missing audit logging
policy[p] {
	domain := domains[_]
	not has_valid_audit_logging(domain)
	p = fugue.deny_resource_with_message(
		domain,
		"OpenSearch domain must have audit logging enabled and configured to send logs to CloudWatch Logs",
	)
}
