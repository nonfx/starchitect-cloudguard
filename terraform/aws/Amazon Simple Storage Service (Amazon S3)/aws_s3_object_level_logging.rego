package rules.aws_s3_object_level_logging

import data.fugue

__rego__metadoc__ := {
	"id": "3.8",
	"title": "Ensure that Object-level logging for write events is enabled for S3 bucket",
	"description": "S3 object-level API operations such as GetObject, DeleteObject, and PutObject are called data events. By default, CloudTrail trails don't log data events and so it is recommended to enable Object-level logging for S3 buckets.",
	"custom": {"controls":{"CIS-AWS-Foundations-Benchmark_v3.0.0":["CIS-AWS-Foundations-Benchmark_v3.0.0_3.8"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

s3_buckets := {bucket.id: bucket | bucket := fugue.resources("aws_s3_bucket")[_]}

cloudtrails := fugue.resources("aws_cloudtrail")

valid_read_write_types := ["WriteOnly", "All"]

s3_object_logging_enabled_for_all(trail) {
	count(trail.event_selector) > 0
	read_write_type := trail.event_selector[_].read_write_type
	valid_read_write_types[_] == read_write_type
	count(trail.event_selector[_].data_resource) > 0
	trail.event_selector[_].data_resource[_].type == "AWS::S3::Object"
	trail.event_selector[_].data_resource[_].values[_] == "arn:aws:s3"
}

s3_object_logging_enabled_for_bucket(trail, bucket) {
	count(trail.event_selector) > 0
	read_write_type := trail.event_selector[_].read_write_type
	valid_read_write_types[_] == read_write_type
	count(trail.event_selector[_].data_resource) > 0
	trail.event_selector[_].data_resource[_].type == "AWS::S3::Object"
	value := trail.event_selector[_].data_resource[_].values[_]
	contains(value, bucket.id)
}

bucket_monitored_by_cloudtrail(bucket) {
	trail := cloudtrails[_]
	s3_object_logging_enabled_for_all(trail)
}

bucket_monitored_by_cloudtrail(bucket) {
	trail := cloudtrails[_]
	s3_object_logging_enabled_for_bucket(trail, bucket)
}

policy[p] {
	bucket := s3_buckets[_]
	bucket_monitored_by_cloudtrail(bucket)
	p = fugue.allow_resource(bucket)
}

policy[p] {
	bucket := s3_buckets[_]
	not bucket_monitored_by_cloudtrail(bucket)
	p = fugue.deny_resource_with_message(bucket, sprintf("S3 bucket '%s' does not have object-level logging enabled for write events in any CloudTrail", [bucket.id]))
}
