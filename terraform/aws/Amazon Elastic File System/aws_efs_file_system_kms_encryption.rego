package rules.aws_efs_file_system_kms_encryption

import data.fugue

__rego__metadoc__ := {
	"id": "2.4.1",
	"title": "Ensure that encryption is enabled for EFS file systems",
	"description": "EFS data should be encrypted at rest using AWS KMS (Key Management Service).",
	"custom": {"controls":{"CIS-AWS-Foundations-Benchmark_v3.0.0":["CIS-AWS-Foundations-Benchmark_v3.0.0_2.4.1"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

file_systems := fugue.resources("aws_efs_file_system")

file_system_kms_encryption_enabled(fs) {
	fs.kms_key_id != null
	fs.encrypted == true
}

file_system_kms_encryption_not_enabled(fs) {
	not fs.encrypted
}

file_system_kms_encryption_not_enabled(fs) {
	not fs.kms_key_id
}

policy[p] {
	fs := file_systems[_]
	fs_id := fs.id
	file_system_kms_encryption_not_enabled(fs)
	msg := sprintf("EFS '%s' is not configured to use SSE-KMS.", [fs_id])
	p = fugue.deny_resource_with_message(fs, msg)
}

policy[p] {
	fs := file_systems[_]
	file_system_kms_encryption_enabled(fs)
	p = fugue.allow_resource(fs)
}
