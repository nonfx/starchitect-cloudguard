package rules.gcp_storage_uniform_bucket_access

import data.fugue

__rego__metadoc__ := {
	"id": "5.2",
	"title": "Ensure uniform bucket-level access is enabled for Cloud Storage buckets",
	"description": "Uniform bucket-level access ensures consistent use of IAM permissions and simplifies access management.",
	"custom": {"severity":"Medium","controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_5.2"]},"author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all storage bucket
google_storage_bucket = fugue.resources("google_storage_bucket")

# Main policy evaluation rule
policy[p] {
	bucket := google_storage_bucket[_]

	# Check if uniform bucket-level access is enabled
	not bucket.uniform_bucket_level_access

	# Create deny message for non-compliant resources
	p = fugue.deny_resource_with_message(bucket, sprintf(
		"Bucket '%v' does not have uniform bucket-level access enabled. Enable it for consistent IAM-based access control.",
		[bucket.name],
	))
}

# Allow rule for compliant resources
policy[p] {
	bucket := google_storage_bucket[_]
	bucket.uniform_bucket_level_access
	p = fugue.allow_resource(bucket)
}
