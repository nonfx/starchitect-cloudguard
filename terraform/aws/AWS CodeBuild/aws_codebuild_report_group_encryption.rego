package rules.codebuild_report_group_encryption

import data.fugue

__rego__metadoc__ := {
	"id": "CodeBuild.7",
	"title": "CodeBuild report group exports should be encrypted at rest",
	"description": "CodeBuild report group exports must be encrypted at rest to protect test results stored in S3 buckets.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_CodeBuild.7"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

codebuild_report_groups = fugue.resources("aws_codebuild_report_group")

# Helper function to check if encryption is properly configured
is_encrypted(report_group) {
	export_config := report_group.export_config[_]
	s3_dest := export_config.s3_destination[_]
	s3_dest.encryption_disabled != true
	s3_dest.encryption_key != null
}

# Policy rule for allowing properly encrypted report groups
policy[p] {
	report_group := codebuild_report_groups[_]
	is_encrypted(report_group)
	p = fugue.allow_resource(report_group)
}

# Policy rule for denying unencrypted report groups
policy[p] {
	report_group := codebuild_report_groups[_]
	not is_encrypted(report_group)
	p = fugue.deny_resource_with_message(
		report_group,
		"CodeBuild report group exports must be encrypted at rest using a KMS key",
	)
}
