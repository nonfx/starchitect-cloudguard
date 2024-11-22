package rules.elasticsearch_dedicated_master_nodes

import data.fugue

__rego__metadoc__ := {
	"id": "ES.7",
	"title": "Elasticsearch domains should be configured with at least three dedicated master nodes",
	"description": "This control checks whether Elasticsearch domains have at least three dedicated master nodes for high availability and fault tolerance.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_ES.7"]}, "severity": "Medium"},
}

resource_type := "MULTIPLE"

elasticsearch_domains = fugue.resources("aws_elasticsearch_domain")

# Helper function to check if domain has sufficient dedicated master nodes
has_sufficient_master_nodes(domain) {
	domain.cluster_config[_].dedicated_master_enabled == true
	domain.cluster_config[_].dedicated_master_count >= 3
}

policy[p] {
	domain := elasticsearch_domains[_]
	has_sufficient_master_nodes(domain)
	p = fugue.allow_resource(domain)
}

policy[p] {
	domain := elasticsearch_domains[_]
	not has_sufficient_master_nodes(domain)
	p = fugue.deny_resource_with_message(domain, "Elasticsearch domain must have at least three dedicated master nodes enabled for high availability")
}
