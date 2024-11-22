package rules.aws_kms_key_rotation

import data.fugue

__rego__metadoc__ := {
	"id": "3.6",
	"title": "Ensure rotation for customer-created symmetric CMKs is enabled",
	"description": "AWS Key Management Service (KMS) allows customers to rotate the backing key which is key material stored within the KMS which is tied to the key ID of the customercreated customer master key (CMK). It is the backing key that is used to perform cryptographic operations such as encryption and decryption. Automated key rotation currently retains all prior backing keys so that decryption of encrypted data can take place transparently. It is recommended that CMK key rotation be enabled for symmetric keys. Key rotation can not be enabled for any asymmetric CMK",
	"custom": {"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_3.6"]}, "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

kms_keys := fugue.resources("aws_kms_key")

key_rotation(key) {
	key.enable_key_rotation == true
}

policy[p] {
	key := kms_keys[_]
	not key_rotation(key)
	p = fugue.deny_resource_with_message(key, "key rotation is not enabled")
}

policy[p] {
	key = kms_keys[_]
	key_rotation(key)
	p = fugue.allow_resource(key)
}
