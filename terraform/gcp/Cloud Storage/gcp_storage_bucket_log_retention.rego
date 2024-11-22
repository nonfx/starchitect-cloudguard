package rules.gcp_storage_bucket_log_retention

import data.fugue

__rego__metadoc__ := {
	"id": "2.3",
	"title": "Ensure That Retention Policies on Cloud Storage Buckets Used for Exporting Logs Are Configured Using Bucket Lock",
	"description": "Storage buckets used for exporting logs must have retention policies configured with Bucket Lock to prevent unauthorized deletion of logs.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.3"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all storage buckets
buckets = fugue.resources("google_storage_bucket")

# Helper to check if bucket has valid retention policy with bucket lock
has_valid_retention_policy(bucket) {
	bucket.retention_policy[_].is_locked == true
	bucket.retention_policy[_].retention_period > 0
}

# Allow buckets with proper retention policy and bucket lock
policy[p] {
	bucket := buckets[_]
	has_valid_retention_policy(bucket)
	p = fugue.allow_resource(bucket)
}

# Deny buckets without proper retention policy or bucket lock
policy[p] {
	bucket := buckets[_]
	not has_valid_retention_policy(bucket)
	p = fugue.deny_resource_with_message(bucket, "Storage bucket must have a retention policy configured with Bucket Lock enabled and a retention period greater than 0")
}
