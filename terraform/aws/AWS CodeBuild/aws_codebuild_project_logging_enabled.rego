package rules.codebuild_project_logging_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "CodeBuild.4",
	"title": "CodeBuild project environments should have a logging AWS Configuration",
	"description": "CodeBuild projects must have at least one logging option enabled (S3 or CloudWatch) for security monitoring and forensics.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_CodeBuild.4"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

codebuild_projects = fugue.resources("aws_codebuild_project")

# Helper function to check if CloudWatch logs are enabled
has_cloudwatch_logs(project) {
	project.logs_config[_].cloudwatch_logs[_].status == "ENABLED"
}

# Helper function to check if S3 logs are enabled
has_s3_logs(project) {
	project.logs_config[_].s3_logs[_].status == "ENABLED"
}

# Policy rule that checks if at least one logging option is enabled
policy[p] {
	project := codebuild_projects[_]
	has_cloudwatch_logs(project)
	p = fugue.allow_resource(project)
}

policy[p] {
	project := codebuild_projects[_]
	has_s3_logs(project)
	p = fugue.allow_resource(project)
}

policy[p] {
	project := codebuild_projects[_]
	not has_cloudwatch_logs(project)
	not has_s3_logs(project)
	p = fugue.deny_resource_with_message(project, "CodeBuild project must have either CloudWatch or S3 logging enabled")
}
