package rules.tf_aws_s3_mfa_delete

import data.aws.s3.s3_library as lib
import data.fugue

__rego__metadoc__ := {
	"id": "2.1.2",
	"title": "Ensure MFA Delete is enabled on S3 buckets",
	"description": "Once MFA Delete is enabled on your sensitive and classified S3 bucket it requires the user to have two forms of authentication.",
	"custom": {
		"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_2.1.2"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

s3_buckets = fugue.resources("aws_s3_bucket")

s3_bucket_versioning = fugue.resources("aws_s3_bucket_versioning")

mfa_delete_enabled(bucket) {
	versioning := s3_bucket_versioning[_]
	versioning.bucket == bucket.id
	versioning.versioning_configuration[_].mfa_delete == "Enabled"
}

policy[p] {
	bucket := s3_buckets[_]
	mfa_delete_enabled(bucket)
	p = fugue.allow_resource(bucket)
}

policy[p] {
	bucket := s3_buckets[_]
	not mfa_delete_enabled(bucket)
	msg := sprintf("MFA Delete is not enabled on this S3 bucket %s", [bucket.id])
	p = fugue.deny_resource_with_message(bucket, msg)
}
