package rules.codebuild_environment_credentials

import data.fugue

__rego__metadoc__ := {
	"id": "CodeBuild.2",
	"title": "CodeBuild project environment variables should not contain clear text credentials",
	"description": "CodeBuild projects must not store AWS credentials as environment variables to prevent unauthorized access and data exposure.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_CodeBuild.2"]}, "severity": "Critical", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

codebuild_projects = fugue.resources("aws_codebuild_project")

# List of sensitive environment variable names
sensitive_env_vars = [
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
]

# Helper function to check if environment variables contain credentials
has_credentials_in_env_vars(project) {
	env := project.environment[_].environment_variable[_]
	sensitive_env_vars[_] == env.name
	env.type != "PARAMETER_STORE"
	env.type != "SECRETS_MANAGER"
}

policy[p] {
	project := codebuild_projects[_]
	not has_credentials_in_env_vars(project)
	p = fugue.allow_resource(project)
}

policy[p] {
	project := codebuild_projects[_]
	has_credentials_in_env_vars(project)
	p = fugue.deny_resource_with_message(project, "CodeBuild project contains AWS credentials in environment variables. Use AWS Systems Manager Parameter Store or Secrets Manager instead.")
}
