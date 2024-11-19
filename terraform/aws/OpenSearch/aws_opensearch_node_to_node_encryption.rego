package rules.opensearch_node_to_node_encryption

import data.fugue

__rego__metadoc__ := {
	"id": "Opensearch.3",
	"title": "OpenSearch domains should encrypt data sent between nodes",
	"description": "OpenSearch domains must implement node-to-node encryption to secure intra-cluster communications and protect data in transit.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Opensearch.3"]}, "severity": "Medium", "author": "llmagent", "reviewer": "ssghait.007@gmail.com"},
}

# Resource type declaration
resource_type := "MULTIPLE"

# Get all OpenSearch domains
opensearch_domains = fugue.resources("aws_opensearch_domain")

# Helper function to check if node-to-node encryption is enabled
is_node_to_node_encrypted(domain) {
	domain.node_to_node_encryption[_].enabled == true
}

# Allow rule for compliant domains
policy[p] {
	domain := opensearch_domains[_]
	is_node_to_node_encrypted(domain)
	p = fugue.allow_resource(domain)
}

# Deny rule for non-compliant domains
policy[p] {
	domain := opensearch_domains[_]
	not is_node_to_node_encrypted(domain)
	p = fugue.deny_resource_with_message(domain, "OpenSearch domain must have node-to-node encryption enabled")
}
