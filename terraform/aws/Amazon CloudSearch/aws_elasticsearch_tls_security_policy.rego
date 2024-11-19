package rules.elasticsearch_tls_security_policy

import data.fugue

__rego__metadoc__ := {
	"id": "ES.8",
	"title": "Elasticsearch domains should be encrypted using the latest TLS security policy",
	"description": "Elasticsearch domains must use the latest TLS security policy (Policy-Min-TLS-1-2-PFS-2023-10) for encrypted connections to ensure data security.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_ES.8"]}, "severity": "Medium", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

elasticsearch_domains = fugue.resources("aws_elasticsearch_domain")

# Helper to check if domain uses latest TLS policy
has_latest_tls_policy(domain) {
	domain.domain_endpoint_options[_].tls_security_policy == "Policy-Min-TLS-1-2-PFS-2023-10"
}

# Helper to check if HTTPS is enforced
has_enforce_https(domain) {
	domain.domain_endpoint_options[_].enforce_https == true
}

policy[p] {
	domain := elasticsearch_domains[_]
	has_latest_tls_policy(domain)
	has_enforce_https(domain)
	p = fugue.allow_resource(domain)
}

policy[p] {
	domain := elasticsearch_domains[_]
	not has_latest_tls_policy(domain)
	p = fugue.deny_resource_with_message(domain, "Elasticsearch domain is not using the latest TLS security policy (Policy-Min-TLS-1-2-PFS-2023-10)")
}

policy[p] {
	domain := elasticsearch_domains[_]
	not has_enforce_https(domain)
	p = fugue.deny_resource_with_message(domain, "Elasticsearch domain does not enforce HTTPS connections")
}
