package rules.tf_aws_s3_data_discovered_classified_secured

import data.aws.s3.s3_library as lib
import data.fugue

__rego__metadoc__ := {
	"id": "2.1.3",
	"title": "Ensure all data in Amazon S3 has been discovered, classified, and secured when required",
	"description": "Amazon S3 buckets can contain sensitive data, that for security purposes should be discovered, monitored, classified and protected. Macie along with other 3rd party tools can automatically provide an inventory of Amazon S3 buckets.",
	"custom": {
		"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_2.1.3"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

buckets := fugue.resources("aws_s3_bucket")

bucket_access = fugue.resources("aws_s3_bucket_public_access_block")

bucket_aencryption = fugue.resources("aws_s3_bucket_server_side_encryption_configuration")

bucket_logging = fugue.resources("aws_s3_bucket_logging")

s3_versionings := fugue.resources("aws_s3_bucket_versioning")

# Check if bucket versioning is enabled
bucket_versioning_enabled(bucket) {
	s3_versioning := s3_versionings[_]
	s3_versioning.bucket == bucket.id
	s3_versioning.versioning_configuration[_].status == "Enabled"
}

# Check if bucket logging is enabled
bucket_logging_enabled(bucket) {
	logs := bucket_logging[_]
	logs.bucket == bucket.id
	logs.target_bucket != null
	logs.target_prefix != null
}

bucket_public_access_blocked(bucket) {
	block = bucket_access[_]
	block.block_public_acls == true
	block.ignore_public_acls == true
	block.block_public_policy == true
	block.restrict_public_buckets == true
}

# Check if bucket encryption is enabled
bucket_encryption_enabled(bucket) {
	encryption := bucket_aencryption[_]
	encryption.bucket == bucket.id
	encryption.rule[_].apply_server_side_encryption_by_default[_].sse_algorithm != ""
}

# Check if the bucket is properly tagged
bucket_properly_tagged(bucket) {
	tags := bucket.tags[_]
	count(tags) > 0
	not empty_value(tags)
}

# Helper function to check for empty tag values
empty_value(val) {
	some k
	val[k] == ""
}

# Check if the bucket meets all security and management requirements
bucket_valid(bucket) {
	bucket_versioning_enabled(bucket)
	bucket_encryption_enabled(bucket)
	bucket_logging_enabled(bucket)
	bucket_public_access_blocked(bucket)
	bucket_properly_tagged(bucket)
}

policy[p] {
	bucket := buckets[_]
	bucket_valid(bucket)
	p := fugue.allow_resource(bucket)
}

policy[p] {
	bucket := buckets[_]
	not bucket_versioning_enabled(bucket)
	msg := sprintf("Bucket '%s' does not have versioning enabled.", [s3_versionings[_].versioning_configuration[_].status])
	p := fugue.deny_resource_with_message(bucket, msg)
}

policy[p] {
	bucket := buckets[_]
	not bucket_encryption_enabled(bucket)
	msg := sprintf("Bucket '%s' does not have encryption enabled.", [bucket.id])
	p := fugue.deny_resource_with_message(bucket, msg)
}

policy[p] {
	bucket := buckets[_]
	not bucket_logging_enabled(bucket)
	msg := sprintf("Bucket '%s' does not have logging enabled.", [bucket.id])
	p := fugue.deny_resource_with_message(bucket, msg)
}

policy[p] {
	bucket := buckets[_]
	not bucket_public_access_blocked(bucket)
	msg := sprintf("Bucket '%s' does not have public access properly blocked.", [bucket.id])
	p := fugue.deny_resource_with_message(bucket, msg)
}

policy[p] {
	bucket := buckets[_]
	not bucket_properly_tagged(bucket)
	msg := sprintf("Bucket '%s' does not have tags.", [bucket.id])
	p := fugue.deny_resource_with_message(bucket, msg)
}
