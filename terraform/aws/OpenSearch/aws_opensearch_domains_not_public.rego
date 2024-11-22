package rules.opensearch_domains_not_public

import data.fugue

__rego__metadoc__ := {
	"id": "Opensearch.2",
	"title": "OpenSearch domains should not be publicly accessible",
	"description": "OpenSearch domains must be deployed within VPCs to prevent public accessibility and ensure secure network configuration.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Opensearch.2"]}, "severity": "Critical"},
}

resource_type := "MULTIPLE"

# Get all OpenSearch domains
opensearch_domains = fugue.resources("aws_opensearch_domain")

# Helper to check if domain is in VPC
is_in_vpc(domain) {
	domain.vpc_options[_]
}

# Allow domains that are in VPC
policy[p] {
	domain := opensearch_domains[_]
	is_in_vpc(domain)
	p = fugue.allow_resource(domain)
}

# Deny domains that are not in VPC
policy[p] {
	domain := opensearch_domains[_]
	not is_in_vpc(domain)
	p = fugue.deny_resource_with_message(domain, "OpenSearch domain must be deployed within a VPC")
}
