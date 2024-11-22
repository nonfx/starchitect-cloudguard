package rules.aws_cloudtrail_kms_encryption

import data.fugue

__rego__metadoc__ := {
	"id": "3.5",
	"title": "Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
	"description": "AWS CloudTrail is a web service that records AWS API calls for an account and makes those logs available to users and resources in accordance with IAM policies. AWS Key Management Service (KMS) is a managed service that helps create and control the encryption keys used to encrypt account data, and uses Hardware Security Modules (HSMs) to protect the security of encryption keys. CloudTrail logs can be configured to leverage server side encryption (SSE) and KMS customer created master keys (CMK) to further protect CloudTrail logs. It is recommended that CloudTrail be configured to use SSE-KMS.",
	"custom": {"controls":{"CIS-AWS-Foundations-Benchmark_v3.0.0":["CIS-AWS-Foundations-Benchmark_v3.0.0_3.5"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

cloudtrails := fugue.resources("aws_cloudtrail")

cloudtrail_kms_encryption_enabled(trail) {
	trail.kms_key_id != null
}

policy[p] {
	trail := cloudtrails[_]
	trail_name := trail.name
	not cloudtrail_kms_encryption_enabled(trail)
	msg := sprintf("CloudTrail '%s' is not configured to use SSE-KMS. Ensure CloudTrail logs are encrypted at rest using KMS CMKs.", [trail_name])
	p = fugue.deny_resource_with_message(trail, msg)
}

policy[p] {
	trail = cloudtrails[_]
	cloudtrail_kms_encryption_enabled(trail)
	p = fugue.allow_resource(trail)
}
