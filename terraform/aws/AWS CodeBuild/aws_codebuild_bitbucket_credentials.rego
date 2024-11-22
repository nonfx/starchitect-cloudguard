package rules.codebuild_bitbucket_credentials

import data.fugue

__rego__metadoc__ := {
	"id": "CodeBuild.1",
	"title": "CodeBuild Bitbucket source repository URLs should not contain sensitive credentials",
	"description": "CodeBuild Bitbucket repository URLs must not contain personal access tokens or credentials to prevent unauthorized access and data exposure.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_CodeBuild.1"]},"severity":"Critical","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

codebuild_projects = fugue.resources("aws_codebuild_project")

# Helper function to check if URL contains credentials
has_credentials(url) {
	contains(url, "@")
}

has_credentials(url) {
	contains(url, ":")
	contains(url, "@")
}

# Check primary source
is_valid_primary_source(project) {
	source := project.source[_]
	source.type == "BITBUCKET"
	not has_credentials(source.location)
}

# Check secondary sources
is_valid_secondary_sources(project) {
	source := project.secondary_sources[_]
	source.type == "BITBUCKET"
	not has_credentials(source.location)
}

policy[p] {
	project := codebuild_projects[_]
	is_valid_primary_source(project)
	is_valid_secondary_sources(project)
	p = fugue.allow_resource(project)
}

policy[p] {
	project := codebuild_projects[_]
	not is_valid_primary_source(project)
	p = fugue.deny_resource_with_message(project, "CodeBuild project primary source contains credentials in Bitbucket URL")
}

policy[p] {
	project := codebuild_projects[_]
	not is_valid_secondary_sources(project)
	p = fugue.deny_resource_with_message(project, "CodeBuild project secondary source contains credentials in Bitbucket URL")
}
