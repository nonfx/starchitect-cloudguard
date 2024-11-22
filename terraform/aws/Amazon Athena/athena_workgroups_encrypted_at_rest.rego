package rules.athena_workgroups_encrypted_at_rest

import data.fugue

__rego__metadoc__ := {
	"id": "Athena.1",
	"title": "Athena workgroups should be encrypted at rest",
	"description": "This control checks if an Athena workgroup is encrypted at rest. The control fails if an Athena workgroup isn't encrypted at rest.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_Athena.1"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

athena_workgroups = fugue.resources("aws_athena_workgroup")

valid_encryption_options = ["SSE_KMS", "CSE_KMS"]

is_encrypted(workgroup) {
	workgroup.configuration[_].result_configuration[_].encryption_configuration[_].encryption_option == "SSE_S3"
}

is_encrypted(workgroup) {
	workgroup.configuration[_].result_configuration[_].encryption_configuration[_].encryption_option == valid_encryption_options[_]
	workgroup.configuration[_].result_configuration[_].encryption_configuration[_].kms_key_arn != null
}

policy[p] {
	workgroup := athena_workgroups[_]
	is_encrypted(workgroup)
	p = fugue.allow_resource(workgroup)
}

policy[p] {
	workgroup := athena_workgroups[_]
	not is_encrypted(workgroup)
	p = fugue.deny_resource_with_message(workgroup, "Athena workgroup is not encrypted at rest or missing KMS key ARN")
}
