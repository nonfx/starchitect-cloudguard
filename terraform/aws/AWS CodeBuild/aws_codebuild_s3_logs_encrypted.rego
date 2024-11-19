package rules.codebuild_s3_logs_encrypted

import data.fugue

__rego__metadoc__ := {
	"id": "CodeBuild.3",
	"title": "CodeBuild S3 logs should be encrypted",
	"description": "AWS CodeBuild S3 logs must be encrypted at rest to enhance data protection and access control through AWS authentication.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_CodeBuild.3"]}, "severity": "Low", "author": "llmagent", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

codebuild_projects = fugue.resources("aws_codebuild_project")

# Helper function to check if S3 logs are encrypted
is_s3_logs_encrypted(project) {
	logs := project.logs_config[_].s3_logs[_]
	logs.encryption_disabled == false
}

# Helper function to check if S3 logs are configured
has_s3_logs(project) {
	project.logs_config[_].s3_logs[_].status == "ENABLED"
}

policy[p] {
	project := codebuild_projects[_]
	has_s3_logs(project)
	is_s3_logs_encrypted(project)
	p = fugue.allow_resource(project)
}

policy[p] {
	project := codebuild_projects[_]
	has_s3_logs(project)
	not is_s3_logs_encrypted(project)
	p = fugue.deny_resource_with_message(project, "CodeBuild project S3 logs must be encrypted")
}

policy[p] {
	project := codebuild_projects[_]
	not has_s3_logs(project)
	p = fugue.allow_resource(project)
}
