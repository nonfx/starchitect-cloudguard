package rules.aws_lightsail_bucket_instance_attachment

import data.fugue

__rego__metadoc__ := {
	"id": "3.8",
	"title": "Ensure Lightsail instances are attached to the buckets",
	"description": "Attaching an Amazon Lightsail instance to a Lightsail storage bucket gives it full programmatic access to the bucket and its objects",
	"custom": {"controls":{"CIS-AWS-Compute-Services-Benchmark_v1.0.0":["CIS-AWS-Compute-Services-Benchmark_v1.0.0_3.8"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

lightsail_buckets := fugue.resources("aws_lightsail_bucket")

lightsail_instances := fugue.resources("aws_lightsail_instance")

lightsail_bucket_access_keys := fugue.resources("aws_lightsail_bucket_access_key")

# Check if a bucket has at least one instance attached
bucket_has_instance_attached(bucket) {
	access_key := lightsail_bucket_access_keys[_]
	access_key.bucket_name == bucket.id
}

policy[p] {
	bucket := lightsail_buckets[_]
	bucket_has_instance_attached(bucket)
	p := fugue.allow_resource(bucket)
}

policy[p] {
	bucket := lightsail_buckets[_]
	not bucket_has_instance_attached(bucket)
	p := fugue.deny_resource_with_message(bucket, sprintf("Lightsail bucket '%s' does not have any instances attached", [bucket.name]))
}

policy[p] {
	count(lightsail_buckets) == 0
	p := fugue.allow_resource("No Lightsail buckets found")
}
