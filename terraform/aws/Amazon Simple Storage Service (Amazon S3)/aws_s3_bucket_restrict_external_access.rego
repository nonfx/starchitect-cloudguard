package rules.s3_bucket_restrict_external_access

import data.fugue

__rego__metadoc__ := {
	"id": "S3.6",
	"title": "S3 general purpose bucket policies should restrict access to other AWS accounts",
	"description": "S3 bucket policies must restrict access to other AWS accounts by preventing specific actions and implementing proper access controls.",
	"custom": {"severity":"High","controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_S3.6"]},"author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all S3 buckets and their policies
buckets = fugue.resources("aws_s3_bucket")

bucket_policies = fugue.resources("aws_s3_bucket_policy")

# List of blacklisted actions
blacklisted_actions = [
	"s3:DeleteBucketPolicy",
	"s3:PutBucketAcl",
	"s3:PutBucketPolicy",
	"s3:PutEncryptionConfiguration",
	"s3:PutObjectAcl",
]

# Helper to check if a principal is from an external AWS account
is_external_principal(principal) {
	startswith(principal, "arn:aws:iam:")
	not startswith(principal, "arn:aws:iam::${data.aws_caller_identity.current.account_id}")
}

# Helper to check if statement contains blacklisted actions
has_blacklisted_action(actions) {
	action := actions[_]
	blacklisted_actions[_] == action
}

has_blacklisted_action(action) {
	blacklisted_actions[_] == action
}

# Allow if bucket has no policy or policy doesn't allow blacklisted actions to external accounts
policy[p] {
	bucket := buckets[_]
	not has_risky_policy(bucket)
	p = fugue.allow_resource(bucket)
}

# Deny if bucket policy allows blacklisted actions to external accounts
policy[p] {
	bucket := buckets[_]
	has_risky_policy(bucket)
	msg := sprintf("S3 bucket '%v' policy allows blacklisted actions for external AWS accounts", [bucket.name])
	p = fugue.deny_resource_with_message(bucket, msg)
}

# Helper to check if bucket has risky policy
has_risky_policy(bucket) {
	policy := bucket_policies[_]
	policy.bucket == bucket.id
	statement := json.unmarshal(policy.policy).Statement[_]
	statement.Effect == "Allow"
	principal := statement.Principal.AWS
	is_external_principal(principal)
	has_blacklisted_action(statement.Action)
}
