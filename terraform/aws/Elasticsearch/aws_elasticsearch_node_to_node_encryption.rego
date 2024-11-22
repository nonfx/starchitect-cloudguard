package rules.elasticsearch_node_to_node_encryption

import data.fugue

__rego__metadoc__ := {
	"id": "ES.3",
	"title": "Elasticsearch domains should encrypt data sent between nodes",
	"description": "Elasticsearch domains must enable node-to-node encryption to secure intra-cluster communications and prevent potential eavesdropping attacks.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_ES.3"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all Elasticsearch domains
es_domains = fugue.resources("aws_elasticsearch_domain")

# Helper to check if node-to-node encryption is enabled
is_node_encryption_enabled(domain) {
	domain.node_to_node_encryption[_].enabled == true
}

# Allow if node-to-node encryption is enabled
policy[p] {
	domain := es_domains[_]
	is_node_encryption_enabled(domain)
	p = fugue.allow_resource(domain)
}

# Deny if node-to-node encryption is disabled or not configured
policy[p] {
	domain := es_domains[_]
	not is_node_encryption_enabled(domain)
	p = fugue.deny_resource_with_message(domain, "Elasticsearch domain must have node-to-node encryption enabled")
}
