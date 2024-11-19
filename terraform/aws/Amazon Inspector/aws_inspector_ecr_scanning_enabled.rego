package rules.inspector_ecr_scanning_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "Inspector.2",
	"title": "Amazon Inspector ECR scanning should be enabled",
	"description": "This control checks if Amazon Inspector ECR scanning is enabled for container images. Enhanced scanning helps identify software vulnerabilities in container images.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Inspector.2"]}, "severity": "High", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

ecr_repositories = fugue.resources("aws_ecr_repository")

# Helper to check if scanning is enabled
is_scanning_enabled(repo) {
	repo.image_scanning_configuration[_].scan_on_push == true
}

policy[p] {
	repo := ecr_repositories[_]
	is_scanning_enabled(repo)
	p = fugue.allow_resource(repo)
}

policy[p] {
	repo := ecr_repositories[_]
	not is_scanning_enabled(repo)
	p = fugue.deny_resource_with_message(repo, "ECR repository does not have image scanning enabled on push")
}
