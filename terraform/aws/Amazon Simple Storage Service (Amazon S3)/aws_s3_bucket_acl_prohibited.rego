package rules.s3_bucket_acl_prohibited

import data.fugue

__rego__metadoc__ := {
	"id": "S3.12",
	"title": "ACLs should not be used to manage user access to S3 general purpose buckets",
	"description": "This control checks if S3 buckets use ACLs for managing user access. ACLs are legacy access control mechanisms and bucket policies or IAM policies should be used instead.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_S3.12"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type = "MULTIPLE"

# Get all S3 buckets and ownership controls
buckets = fugue.resources("aws_s3_bucket")

ownership_controls = fugue.resources("aws_s3_bucket_ownership_controls")

# Check if bucket has ACLs disabled through ownership controls
is_acl_disabled(bucket_id) {
	ownership := ownership_controls[_]
	ownership.bucket == bucket_id
	ownership.rule[_].object_ownership == "BucketOwnerEnforced"
}

# Allow buckets with ACLs disabled
policy[p] {
	bucket := buckets[_]
	is_acl_disabled(bucket.id)
	p = fugue.allow_resource(bucket)
}

# Deny buckets with ACLs enabled or missing ownership controls
policy[p] {
	bucket := buckets[_]
	not is_acl_disabled(bucket.id)
	p = fugue.deny_resource_with_message(
		bucket,
		sprintf("%s must have ACLs disabled by setting object ownership to BucketOwnerEnforced", [bucket.id]),
	)
}
