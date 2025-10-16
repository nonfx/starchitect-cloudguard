package rules.opensearch_tls_latest

import data.fugue

__rego__metadoc__ := {
	"id": "Opensearch.8",
	"title": "Connections to OpenSearch domains should be encrypted using the latest TLS security policy",
	"description": "OpenSearch domains should be configured to use the latest TLS security policy for encrypted connections to ensure data protection in transit.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_Opensearch.8"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

opensearch_domains = fugue.resources("aws_opensearch_domain")

# Helper function to check if domain uses latest TLS policy and enforces HTTPS
is_secure_tls(domain) {
	domain.domain_endpoint_options[_].tls_security_policy == "Policy-Min-TLS-1-2-PFS-2023-10"
	domain.domain_endpoint_options[_].enforce_https == true
}

policy[p] {
	domain := opensearch_domains[_]
	is_secure_tls(domain)
	p = fugue.allow_resource(domain)
}

policy[p] {
	domain := opensearch_domains[_]
	not is_secure_tls(domain)
	p = fugue.deny_resource_with_message(domain, "OpenSearch domain must use the latest TLS security policy and enforce HTTPS connections")
}
