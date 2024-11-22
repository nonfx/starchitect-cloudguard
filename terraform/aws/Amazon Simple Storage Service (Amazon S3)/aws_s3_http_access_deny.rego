package rules.tf_aws_s3_deny_http_access

import data.aws.iam.policy_document_library as doclib
import data.aws.s3.s3_library as lib
import data.fugue

__rego__metadoc__ := {
	"id": "2.1.1",
	"title": "Ensure S3 Bucket Policy is set to deny HTTP requests",
	"description": "At the Amazon S3 bucket level, you can configure permissions through a bucket policy making the objects accessible only through HTTPS.",
	"custom": {
		"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_2.1.1"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

# This checks if this statement deny HTTP requests
specifies_insecure_transport(statement) {
	insecure_transport_values = as_array(statement.Condition.Bool["aws:SecureTransport"])
	insecure_transport_values == ["false"]
	statement.Effect == "Deny"

	actions = as_array(statement.Action)
	related_actions = {"s3:GetObject", "s3:*", "*"}
	related_actions[actions[_]]
}

buckets = fugue.resources("aws_s3_bucket")

# A valid policy denies `specifies_insecure_transport` statements
valid_buckets[bucket_id] = bucket {
	bucket = buckets[bucket_id]
	policies = lib.bucket_policies_for_bucket(bucket)
	pol = policies[_]
	doc = doclib.to_policy_document(pol)
	statements = as_array(doc.Statement)
	specifies_insecure_transport(statements[_])
}

resource_type := "MULTIPLE"

policy[j] {
	b = valid_buckets[_]
	j = fugue.allow_resource(b)
}

policy[j] {
	b = buckets[id]
	not valid_buckets[id]
	j = fugue.deny_resource(b)
}

# Utility: turns anything into an array, if it's not an array already.
as_array(x) = [x] {
	not is_array(x)
}

else = x
