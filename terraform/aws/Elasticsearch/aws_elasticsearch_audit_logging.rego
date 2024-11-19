package rules.elasticsearch_audit_logging

import data.fugue

__rego__metadoc__ := {
	"id": "ES.5",
	"title": "Elasticsearch domains should have audit logging enabled",
	"description": "Elasticsearch domains must enable audit logging to track user activities and maintain security compliance through CloudWatch Logs.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_ES.5"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

# Get all Elasticsearch domains
domains = fugue.resources("aws_elasticsearch_domain")

# Helper to check if audit logging is enabled and properly configured
has_audit_logging(domain) {
	log_config := domain.log_publishing_options[_]
	log_config.log_type == "AUDIT_LOGS"
	log_config.enabled == true
	log_config.cloudwatch_log_group_arn != null
}

# Allow if domain has audit logging enabled
policy[p] {
	domain := domains[_]
	has_audit_logging(domain)
	p = fugue.allow_resource(domain)
}

# Deny if domain does not have audit logging enabled
policy[p] {
	domain := domains[_]
	not has_audit_logging(domain)
	p = fugue.deny_resource_with_message(domain, "Elasticsearch domain must have audit logging enabled and configured to send logs to CloudWatch Logs")
}
