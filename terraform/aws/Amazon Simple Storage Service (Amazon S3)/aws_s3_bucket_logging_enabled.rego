package rules.s3_bucket_logging_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "S3.9",
	"title": "S3 general purpose buckets should have server access logging enabled",
	"description": "This control checks whether server access logging is enabled for S3 buckets. Server access logging provides detailed records of requests made to buckets and assists in security audits.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_S3.9"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all S3 buckets and logging configurations
s3_buckets = fugue.resources("aws_s3_bucket")

s3_bucket_loggings = fugue.resources("aws_s3_bucket_logging")

# Helper function to check if bucket has logging enabled
has_logging(bucket_id) {
	logging := s3_bucket_loggings[_]
	logging.bucket == bucket_id
	logging.target_bucket != null
	logging.target_prefix != null
}

# Helper function to check if bucket is a logging target
is_logging_target(bucket_id) {
	logging := s3_bucket_loggings[_]
	logging.target_bucket == bucket_id
}

# Allow buckets that have logging enabled
policy[p] {
	bucket := s3_buckets[_]
	has_logging(bucket.id)
	p = fugue.allow_resource(bucket)
}

# Allow buckets that are logging targets
policy[p] {
	bucket := s3_buckets[_]
	is_logging_target(bucket.id)
	p = fugue.allow_resource(bucket)
}

# Deny buckets that neither have logging enabled nor are logging targets
policy[p] {
	bucket := s3_buckets[_]
	not has_logging(bucket.id)
	not is_logging_target(bucket.id)
	p = fugue.deny_resource_with_message(bucket, "S3 bucket does not have server access logging enabled")
}
