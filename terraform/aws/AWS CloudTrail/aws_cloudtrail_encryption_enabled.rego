package rules.cloudtrail_encryption_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "CloudTrail.2",
	"title": "CloudTrail should have encryption at-rest enabled",
	"description": "CloudTrail trails must use AWS KMS key encryption for server-side encryption of log files at rest.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudTrail.2"]}, "severity": "Medium", "author": "llmagent", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

cloudtrails = fugue.resources("aws_cloudtrail")

# Helper to check if KMS encryption is enabled
has_kms_encryption(trail) {
	trail.kms_key_id != null
	trail.kms_key_id != ""
}

policy[p] {
	trail := cloudtrails[_]
	has_kms_encryption(trail)
	p = fugue.allow_resource(trail)
}

policy[p] {
	trail := cloudtrails[_]
	not has_kms_encryption(trail)
	p = fugue.deny_resource_with_message(trail, "CloudTrail trail must be encrypted using KMS key encryption")
}

policy[p] {
	count(cloudtrails) == 0
	p = fugue.missing_resource_with_message("aws_cloudtrail", "No CloudTrail trails found")
}
