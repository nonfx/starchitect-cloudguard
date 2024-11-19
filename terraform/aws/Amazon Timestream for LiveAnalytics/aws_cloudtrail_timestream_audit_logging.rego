package rules.aws_cloudtrail_timestream_audit_logging

import data.fugue

__rego__metadoc__ := {
	"author": "rajat@nonfx.com",
	"id": "10.6",
	"title": "Ensure Audit Logging is Enabled for Amazon Timestream",
	"description": "Enable AWS CloudTrail to capture and log API calls and activities related to Amazon Timestream. Configure CloudTrail to store the logs in a secure location and regularly review the logs for any unauthorized or suspicious activities.",
	"custom": {
		"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_10.6"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

cloudtrails := fugue.resources("aws_cloudtrail")

s3_buckets := fugue.resources("aws_s3_bucket")

cloudwatch_log_groups := fugue.resources("aws_cloudwatch_log_group")

timestream_databases := fugue.resources("aws_timestreamwrite_database")

bucket_aencryption = fugue.resources("aws_s3_bucket_server_side_encryption_configuration")

trail_logs_timestream_events(trail) {
	some i
	trail.event_selector[i].data_resource[_].type == "AWS::Timestream::Table"
	trail.event_selector[i].include_management_events == true
}

trail_has_encryption(trail) {
	trail.kms_key_id != null
	trail.kms_key_id != ""
}

trail_logs_to_cloudwatch(trail) {
	trail.cloud_watch_logs_group_arn != null
	trail.cloud_watch_logs_group_arn != ""
}

bucket_has_encryption(bucket) {
	encryption := bucket_aencryption[_]
	encryption.bucket == bucket.id
	encryption.rule[_].apply_server_side_encryption_by_default[_].sse_algorithm != ""
}

bucket_has_access_logging(bucket) {
	fugue.resources("aws_s3_bucket_logging")[_].bucket == bucket.id
}

policy[p] {
	count(timestream_databases) > 0
	trail := cloudtrails[_]
	trail_logs_timestream_events(trail)
	trail_has_encryption(trail)
	trail_logs_to_cloudwatch(trail)
	bucket := s3_buckets[trail.s3_bucket_name]
	bucket_has_encryption(bucket)
	bucket_has_access_logging(bucket)
	p = fugue.allow_resource(trail)
}

policy[p] {
	count(timestream_databases) > 0
	trail := cloudtrails[_]
	not trail_logs_timestream_events(trail)
	p = fugue.deny_resource_with_message(trail, "CloudTrail is not configured to log Timestream events")
}

policy[p] {
	count(timestream_databases) > 0
	trail := cloudtrails[_]
	not trail_has_encryption(trail)
	p = fugue.deny_resource_with_message(trail, "CloudTrail is not encrypted to log Timestream events")
}

policy[p] {
	count(timestream_databases) > 0
	trail := cloudtrails[_]
	not trail_logs_to_cloudwatch(trail)
	p = fugue.deny_resource_with_message(trail, "CloudTrail is not configured to send logs to CloudWatch")
}

policy[p] {
	count(timestream_databases) > 0
	trail := cloudtrails[_]
	bucket := s3_buckets[_]
	not bucket_has_encryption(bucket)
	p = fugue.deny_resource_with_message(trail, "S3 bucket used for CloudTrail logs is not encrypted")
}

policy[p] {
	count(timestream_databases) > 0
	trail := cloudtrails[_]
	bucket := s3_buckets[trail.s3_bucket_name]
	not bucket_has_access_logging(bucket)
	p = fugue.deny_resource_with_message(bucket, "S3 bucket used for CloudTrail logs does not have access logging enabled")
}
