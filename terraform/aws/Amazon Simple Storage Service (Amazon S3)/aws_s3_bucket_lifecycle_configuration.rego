package rules.s3_bucket_lifecycle_configuration

import data.fugue

__rego__metadoc__ := {
	"id": "S3.13",
	"title": "S3 general purpose buckets should have Lifecycle configurations",
	"description": "This control checks whether S3 buckets have Lifecycle configurations enabled to manage object transitions and deletions effectively.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_S3.13"]}, "severity": "Low", "author": "Starchitect Agent"},
}

resource_type = "MULTIPLE"

# Get all S3 buckets and ownership controls
buckets = fugue.resources("aws_s3_bucket")

aws_s3_bucket_lifecycle_rule = fugue.resources("aws_s3_bucket_lifecycle_rule")

# Check if bucket has lifecycle rules configured
has_lifecycle_rules(bucket_id) {
	lifecycle := aws_s3_bucket_lifecycle_rule[_]
	lifecycle.bucket == bucket_id
	lifecycle.enabled == true
}

# Allow buckets with lifecycle rules
policy[p] {
	bucket := buckets[_]
	has_lifecycle_rules(bucket.id)
	p = fugue.allow_resource(bucket)
}

# Deny buckets without lifecycle rules
policy[p] {
	bucket := buckets[_]
	not has_lifecycle_rules(bucket.id)
	p = fugue.deny_resource_with_message(bucket, "S3 bucket must have at least one enabled lifecycle rule configured")
}
