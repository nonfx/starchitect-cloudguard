package rules.elasticsearch_encryption_at_rest

import data.fugue

__rego__metadoc__ := {
	"id": "ES.1",
	"title": "Elasticsearch domains should have encryption at-rest enabled",
	"description": "This control checks whether Elasticsearch domains have encryption at rest enabled using AWS KMS. Encryption at rest provides an additional layer of data security and helps meet compliance requirements.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_ES.1"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

# Get all Elasticsearch domains
es_domains = fugue.resources("aws_elasticsearch_domain")

# Helper to check if encryption at rest is enabled
is_encrypted_at_rest(domain) {
	domain.encrypt_at_rest[_].enabled == true
}

# Allow if encryption at rest is enabled
policy[p] {
	domain := es_domains[_]
	is_encrypted_at_rest(domain)
	p = fugue.allow_resource(domain)
}

# Deny if encryption at rest is disabled or not configured
policy[p] {
	domain := es_domains[_]
	not is_encrypted_at_rest(domain)
	p = fugue.deny_resource_with_message(domain, "Elasticsearch domain must have encryption at rest enabled using AWS KMS")
}
