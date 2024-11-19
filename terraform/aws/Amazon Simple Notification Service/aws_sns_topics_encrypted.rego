package rules.sns_topics_encrypted

import data.fugue

__rego__metadoc__ := {
	"id": "SNS.1",
	"title": "SNS topics should be encrypted at-rest using AWS KMS",
	"description": "SNS topics must use AWS KMS for server-side encryption to enhance data protection and access control.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_SNS.1"]}, "severity": "Medium", "author": "llmagent", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

# Get all SNS topics
sns_topics = fugue.resources("aws_sns_topic")

# Check if SNS topic is encrypted with KMS
is_kms_encrypted(topic) {
	topic.kms_master_key_id != null
	topic.kms_master_key_id != ""
}

# Allow topics that are encrypted with KMS
policy[p] {
	topic := sns_topics[_]
	is_kms_encrypted(topic)
	p = fugue.allow_resource(topic)
}

# Deny topics that are not encrypted with KMS
policy[p] {
	topic := sns_topics[_]
	not is_kms_encrypted(topic)
	p = fugue.deny_resource_with_message(topic, "SNS topic must be encrypted at rest using AWS KMS")
}
