package rules.opensearch_data_node_fault_tolerance

import data.fugue

__rego__metadoc__ := {
	"id": "OpenSearch.6",
	"title": "OpenSearch domains should have at least three data nodes",
	"description": "OpenSearch domains must have at least three data nodes and zone awareness enabled for high availability and fault tolerance.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_OpenSearch.6"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

domains := fugue.resources("aws_opensearch_domain")

# Helper to check if domain configuration is valid
is_valid_configuration(domain) {
	config := domain.cluster_config[_]
	config.instance_count >= 3
	config.zone_awareness_enabled == true
}

# Deny if configuration is invalid
policy[p] {
	domain := domains[_]
	not is_valid_configuration(domain)
	p := fugue.deny_resource_with_message(
		domain,
		sprintf("OpenSearch domain '%s' must have at least 3 nodes and zone awareness enabled", [domain.domain_name]),
	)
}

# Allow if configuration is valid
policy[p] {
	domain := domains[_]
	is_valid_configuration(domain)
	p := fugue.allow_resource(domain)
}
