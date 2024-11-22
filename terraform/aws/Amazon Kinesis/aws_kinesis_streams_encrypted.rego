package rules.kinesis_streams_encrypted

import data.fugue

__rego__metadoc__ := {
	"id": "Kinesis.1",
	"title": "Kinesis streams should be encrypted at rest",
	"description": "This control checks if Kinesis Data Streams use server-side encryption at rest using AWS KMS keys. Encryption at rest helps protect stored data from unauthorized access.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Kinesis.1"]}, "severity": "Medium"},
}

resource_type := "MULTIPLE"

# Get all Kinesis stream resources
kinesis_streams = fugue.resources("aws_kinesis_stream")

# Helper function to check if encryption is enabled
is_encrypted(stream) {
	stream.encryption_type == "KMS"
	stream.kms_key_id != null
}

# Allow resources that are properly encrypted
policy[p] {
	stream := kinesis_streams[_]
	is_encrypted(stream)
	p = fugue.allow_resource(stream)
}

# Deny resources that are not properly encrypted
policy[p] {
	stream := kinesis_streams[_]
	not is_encrypted(stream)
	p = fugue.deny_resource_with_message(stream, "Kinesis stream is not encrypted at rest using KMS encryption")
}
