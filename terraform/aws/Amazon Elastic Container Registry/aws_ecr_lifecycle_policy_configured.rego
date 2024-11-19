package rules.ecr_lifecycle_policy_configured

import data.fugue

__rego__metadoc__ := {
	"id": "ECR.3",
	"title": "ECR repositories should have at least one lifecycle policy configured",
	"description": "This control checks if Amazon ECR repositories have at least one lifecycle policy configured. Lifecycle policies help manage container images by automatically cleaning up unused images based on age or count criteria.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_ECR.3"]}, "severity": "Medium", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

# Get all ECR repositories
ecr_repositories = fugue.resources("aws_ecr_repository")

# Get all ECR lifecycle policies
ecr_lifecycle_policies = fugue.resources("aws_ecr_lifecycle_policy")

# Helper to check if repository has lifecycle policy
has_lifecycle_policy(repository) {
	policy := ecr_lifecycle_policies[_]
	policy.repository == repository.name
}

# Allow repositories that have lifecycle policies
policy[p] {
	repository := ecr_repositories[_]
	has_lifecycle_policy(repository)
	p = fugue.allow_resource(repository)
}

# Deny repositories that don't have lifecycle policies
policy[p] {
	repository := ecr_repositories[_]
	not has_lifecycle_policy(repository)
	p = fugue.deny_resource_with_message(repository, "ECR repository does not have a lifecycle policy configured")
}
