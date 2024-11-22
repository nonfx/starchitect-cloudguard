package rules.opensearch_fine_grained_access_control

import data.fugue

__rego__metadoc__ := {
	"id": "Opensearch.7",
	"title": "OpenSearch domains should have fine-grained access control enabled",
	"description": "OpenSearch domains must enable fine-grained access control for enhanced security and access management capabilities.",
	"custom": {"severity": "High", "controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Opensearch.7"]}, "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

opensearch_domains = fugue.resources("aws_opensearch_domain")

is_fine_grained_access_control_enabled(domain) {
	domain.advanced_security_options[_].internal_user_database_enabled == true
	domain.advanced_security_options[_].enabled == true
}

policy[p] {
	domain := opensearch_domains[_]
	is_fine_grained_access_control_enabled(domain)
	p = fugue.allow_resource(domain)
}

policy[p] {
	domain := opensearch_domains[_]
	not is_fine_grained_access_control_enabled(domain)
	p = fugue.deny_resource_with_message(domain, "OpenSearch domain must have fine-grained access control enabled")
}
