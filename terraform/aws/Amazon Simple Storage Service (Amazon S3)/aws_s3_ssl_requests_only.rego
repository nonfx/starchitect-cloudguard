package rules.s3_ssl_required

import data.fugue

__rego__metadoc__ := {
	"id": "S3.5",
	"title": "S3 buckets should require SSL/TLS for all requests",
	"description": "This control checks if S3 buckets require SSL/TLS encryption for all requests by verifying bucket policies include aws:SecureTransport condition.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_S3.5"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all S3 buckets and their policies
buckets = fugue.resources("aws_s3_bucket")

bucket_policies = fugue.resources("aws_s3_bucket_policy")

# Helper to check if statement enforces SSL
is_ssl_enforcing_statement(statement) {
	statement.Effect == "Deny"
	statement.Principal == "*"
	statement.Action == "s3:*"
	statement.Condition.Bool["aws:SecureTransport"] == "false"
}

# Helper to check if policy document has SSL requirement
has_ssl_requirement(policy_doc) {
	statement := policy_doc.Statement[_]
	is_ssl_enforcing_statement(statement)
}

# Allow if bucket has policy requiring SSL
policy[p] {
	bucket := buckets[_]
	policy := bucket_policies[_]
	policy.bucket == bucket.id
	policy_doc := json.unmarshal(policy.policy)
	has_ssl_requirement(policy_doc)
	p = fugue.allow_resource(bucket)
}

# Deny if bucket doesn't have required SSL policy
policy[p] {
	bucket := buckets[_]
	not_has_ssl_policy(bucket)
	p = fugue.deny_resource_with_message(
		bucket,
		"S3 bucket must have a policy that requires SSL/TLS for all requests using aws:SecureTransport condition",
	)
}

# Helper to check if bucket doesn't have SSL policy
not_has_ssl_policy(bucket) {
	policy := bucket_policies[_]
	policy.bucket == bucket.id
	policy_doc := json.unmarshal(policy.policy)
	not has_ssl_requirement(policy_doc)
}

not_has_ssl_policy(bucket) {
	not bucket_has_policy(bucket)
}

# Helper to check if bucket has any policy
bucket_has_policy(bucket) {
	policy := bucket_policies[_]
	policy.bucket == bucket.id
}
