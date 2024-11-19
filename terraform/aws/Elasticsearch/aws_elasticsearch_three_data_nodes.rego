package rules.elasticsearch_three_data_nodes

import data.fugue

__rego__metadoc__ := {
	"id": "ES.6",
	"title": "Elasticsearch domains should have at least three data nodes",
	"description": "This rule ensures Elasticsearch domains are configured with at least three data nodes and zone awareness enabled for high availability.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_ES.6"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

# Helper to check if domain has required node configuration
has_required_nodes(domain) {
	domain.cluster_config[_].instance_count >= 3
	domain.cluster_config[_].zone_awareness_enabled == true
}

# Allow if domain has required node configuration
policy[p] {
	resource = fugue.resources("aws_elasticsearch_domain")[_]
	has_required_nodes(resource)
	p = fugue.allow_resource(resource)
}

# Deny if domain does not have required node configuration
policy[p] {
	resource = fugue.resources("aws_elasticsearch_domain")[_]
	not has_required_nodes(resource)
	p = fugue.deny_resource_with_message(
		resource,
		"Elasticsearch domain must have at least three data nodes and zone awareness enabled",
	)
}
