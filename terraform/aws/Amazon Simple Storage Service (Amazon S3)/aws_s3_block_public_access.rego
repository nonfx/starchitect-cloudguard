package rules.tf_aws_s3_block_public_access

import data.aws.s3.s3_library as lib
import data.fugue

__rego__metadoc__ := {
	"author": "rajat@nonfx.com",
	"id": "2.1.4",
	"title": "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'",
	"description": "Amazon S3 provides Block public access (bucket settings) and Block public access (account settings) to help you manage public access to Amazon S3 resources. By default, S3 buckets and objects are created with public access disabled. However, an IAM principle with sufficient S3 permissions can enable public access at the bucket and/or object level. While enabled, Block public access (bucket settings) prevents an individual bucket, and its contained objects, from becoming publicly accessible. Similarly, Block public access (account settings) prevents all buckets, and contained objects, from becoming publicly accessible across the entire account.",
	"custom": {
		"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_2.1.4"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

buckets = fugue.resources("aws_s3_bucket")

bucket_access_blocks = fugue.resources("aws_s3_bucket_public_access_block")

account_access_blocks = fugue.resources("aws_s3_account_public_access_block")

# Using the `bucket_access_blocks`, we construct a set of bucket IDs that have
# the public access blocked.
blocked_buckets[bucket_name] {
	block = bucket_access_blocks[_]
	bucket_name = block.bucket
	block.block_public_acls == true
	block.ignore_public_acls == true
	block.block_public_policy == true
	block.restrict_public_buckets == true
}

blocked_account {
	block := account_access_blocks[_]
	block.block_public_acls == true
	block.ignore_public_acls == true
	block.block_public_policy == true
	block.restrict_public_buckets == true
}

bucket_is_blocked(bucket) {
	blocked_account
}

bucket_is_blocked(bucket) {
	fugue.input_type != "tf_runtime"
	blocked_buckets[bucket.id]
}

bucket_is_blocked(bucket) {
	blocked_buckets[bucket.bucket]
}

policy[j] {
	b = buckets[bucket_id]
	bucket_is_blocked(b)
	j = fugue.allow_resource(b)
}

policy[j] {
	b = buckets[bucket_id]
	not bucket_is_blocked(b)
	j = fugue.deny_resource(b)
}
