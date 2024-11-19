package rules.aws_lightsail_bucket_access

import data.aws.iam.policy_document_library as lib
import data.fugue

__rego__metadoc__ := {
	"author": "rajat@nonfx.com",
	"id": "3.7",
	"title": "Ensure you are using an IAM policy to manage access to buckets in Lightsail",
	"description": "The following policy grants a user access to manage a specific bucket in the Amazon Lightsail object storage service",
	"custom": {
		"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_3.7"]},
		"severity": "Medium",
	},
}

# All IAM policy objects that have an ID and a `policy` field containing a JSON string.
policies[id] = p {
	ps = fugue.resources("aws_iam_policy")
	p = ps[id]
}

# Check if the policy grants permissions to Lightsail and specific S3 buckets
valid_policy(pol) {
	doc = lib.to_policy_document(pol.policy)
	statements = as_array(doc.Statement)

	# Check if the policy grants permissions to Lightsail
	has_lightsail_access := [s | s = statements[_]; s.Action == "lightsail:*"; s.Resource == "*"]

	# Check if the policy grants permissions to specific S3 buckets
	has_s3_access := [s | s = statements[_]; s.Action == "s3:*"; startswith(s.Resource[_], "arn:aws:s3:::")]

	# The policy is valid if it grants necessary permissions and avoids full administrative access
	count(has_lightsail_access) > 0
	count(has_s3_access) > 0
	not is_full_admin_policy(doc)
}

# Determine if a policy is a "full admin" policy.
is_full_admin_policy(doc) {
	statements = as_array(doc.Statement)
	statement = statements[_]

	statement.Effect == "Allow"
	statement.Action == "*"
	statement.Resource == "*"
}

# Judge policies and invalid policies.
resource_type := "MULTIPLE"

policy[j] {
	pol = policies[id]
	valid_policy(pol)
	j = fugue.allow_resource(pol)
}

policy[j] {
	pol = policies[id]
	not valid_policy(pol)
	j = fugue.deny_resource(pol)
}

# Utility: turns anything into an array, if it's not an array already.
as_array(x) = [x] {
	not is_array(x)
}

else = x
