package rules.aws_cloudtrail_s3_access_logging

import data.fugue

__rego__metadoc__ := {
	"id": "3.4_CloudTrail.7",
	"title": "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
	"description": "S3 Bucket Access Logging generates a log that contains access records for each request made to your S3 bucket. An access log record contains details about the request, such as the request type, the resources specified in the request worked, and the time and date the request was processed. It is recommended that bucket access logging be enabled on the CloudTrail S3 bucket.",
	"custom": {
		"controls": {
			"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_3.4"],
			"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudTrail.7"],
		},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

cloudtrails = fugue.resources("aws_cloudtrail")

buckets = fugue.resources("aws_s3_bucket")

bucket_loggings = fugue.resources("aws_s3_bucket_logging")

buckets_by_name = {bucket.id: bucket | bucket := buckets[_]}

bucket_loggings_by_bucket = {logging.bucket: logging | logging := bucket_loggings[_]}

target_has_access_logging(ct) {
	bucket_name := ct.s3_bucket_name
	bucket := buckets_by_name[bucket_name]
	bucket_has_logging(bucket_name)
}

bucket_has_logging(bucket_name) {
	bucket_loggings_by_bucket[bucket_name]
}

resource_type := "MULTIPLE"

policy[j] {
	ct := cloudtrails[_]
	target_has_access_logging(ct)
	j := fugue.allow_resource(ct)
}

policy[j] {
	ct := cloudtrails[_]
	not target_has_access_logging(ct)
	j := fugue.deny_resource(ct)
}
