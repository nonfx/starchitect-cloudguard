package rules.gcp_storage_bucket_public_access

import data.fugue

__rego__metadoc__ := {
	"id": "5.1",
	"title": "Ensure That Cloud Storage Bucket Is Not Anonymously or Publicly Accessible",
	"description": "Cloud Storage buckets should not allow anonymous or public access to prevent unauthorized data exposure. IAM policies should be properly configured to restrict access.",
	"custom": {"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_5.1"]}, "severity": "Critical", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all storage buckets
buckets = fugue.resources("google_storage_bucket")

bucket_iam_bindings = fugue.resources("google_storage_bucket_iam_binding")

bucket_iam_members = fugue.resources("google_storage_bucket_iam_member")

# Check if member is public
is_public_member(member) {
	member == "allUsers"
}

is_public_member(member) {
	member == "allAuthenticatedUsers"
}

# Check IAM binding for public access
has_public_access(bucket_name) {
	binding := bucket_iam_bindings[_]
	binding.bucket == bucket_name
	member := binding.members[_]
	is_public_member(member)
}

# Check IAM member for public access
has_public_access(bucket_name) {
	member := bucket_iam_members[_]
	member.bucket == bucket_name
	is_public_member(member.member)
}

# Allow buckets without public access
policy[p] {
	bucket := buckets[_]
	not has_public_access(bucket.name)
	p = fugue.allow_resource(bucket)
}

# Deny buckets with public access
policy[p] {
	bucket := buckets[_]
	has_public_access(bucket.name)
	p = fugue.deny_resource_with_message(
		bucket,
		"Cloud Storage bucket should not allow anonymous or public access",
	)
}
