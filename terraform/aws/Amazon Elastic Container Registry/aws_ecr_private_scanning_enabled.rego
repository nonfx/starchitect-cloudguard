package rules.ecr_private_scanning

import data.fugue

__rego__metadoc__ := {
	"id": "ECR.1",
	"title": "ECR private repositories should have image scanning configured",
	"description": "This control checks whether ECR private repositories have image scanning enabled. The control fails if scan_on_push is not enabled.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_ECR.1"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all ECR repositories
ecr_repositories = fugue.resources("aws_ecr_repository")

# Helper to check if scanning is enabled
is_scanning_enabled(repo) {
	repo.image_scanning_configuration[_].scan_on_push == true
}

# Allow repositories with scanning enabled
policy[p] {
	repo := ecr_repositories[_]
	is_scanning_enabled(repo)
	p = fugue.allow_resource(repo)
}

# Deny repositories without scanning enabled
policy[p] {
	repo := ecr_repositories[_]
	not is_scanning_enabled(repo)
	p = fugue.deny_resource_with_message(repo, "ECR repository does not have image scanning enabled. Enable scan on push to identify software vulnerabilities.")
}
