package rules.opensearch_encryption_at_rest

# Import the fugue library for policy evaluation
import data.fugue

# Metadata for the rule including compliance controls and severity
__rego__metadoc__ := {
	"id": "OpenSearch.1",
	"title": "OpenSearch domains should have encryption at rest enabled",
	"description": "OpenSearch domains must enable encryption at rest using AWS KMS with AES-256 for secure data protection.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_OpenSearch.1"]}, "severity": "Medium", "author": "llmagent", "reviewer": "ssghait.007@gmail.com"},
}

# Specify that this rule applies to multiple resource types
resource_type := "MULTIPLE"

# Get all OpenSearch domain resources
opensearch_domains = fugue.resources("aws_opensearch_domain")

# Helper function to check if encryption at rest is enabled
is_encrypted(domain) {
	domain.encrypt_at_rest[_].enabled == true
}

# Allow resources that have encryption enabled
policy[p] {
	domain := opensearch_domains[_]
	is_encrypted(domain)
	p = fugue.allow_resource(domain)
}

# Deny resources that don't have encryption enabled
policy[p] {
	domain := opensearch_domains[_]
	not is_encrypted(domain)
	p = fugue.deny_resource_with_message(domain, "OpenSearch domain must have encryption at rest enabled using AWS KMS")
}
