package rules.ecr_private_tag_immutability

import data.fugue

__rego__metadoc__ := {
	"id": "ECR.2",
	"title": "ECR private repositories should have tag immutability configured",
	"description": "This control checks if private ECR repositories have tag immutability enabled. Immutable tags prevent overwriting of container images, ensuring consistent deployments and reducing security risks.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_ECR.2"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all ECR repositories
ecr_repositories = fugue.resources("aws_ecr_repository")

# Helper to check if tag immutability is enabled
is_tag_immutable(repo) {
	repo.image_tag_mutability == "IMMUTABLE"
}

# Allow repositories with immutable tags
policy[p] {
	repo := ecr_repositories[_]
	is_tag_immutable(repo)
	p = fugue.allow_resource(repo)
}

# Deny repositories without immutable tags
policy[p] {
	repo := ecr_repositories[_]
	not is_tag_immutable(repo)
	p = fugue.deny_resource_with_message(repo, "ECR repository does not have tag immutability enabled. Enable image tag immutability to prevent tag overwriting.")
}
