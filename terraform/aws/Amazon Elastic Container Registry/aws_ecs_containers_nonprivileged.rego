package rules.ecs_containers_nonprivileged

import data.fugue

__rego__metadoc__ := {
	"id": "ECS.4",
	"title": "ECS containers should run as non-privileged",
	"description": "This control checks if ECS containers are running with privileged access. Containers should not have privileged access to ensure proper security isolation.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_ECS.4"]}, "severity": "High", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

# Get all ECS task definitions
task_definitions = fugue.resources("aws_ecs_task_definition")

# Helper to check if container is non-privileged
is_nonprivileged(container) {
	not container.privileged
}

is_nonprivileged(container) {
	container.privileged == false
}

# Helper to check all containers in task definition
all_containers_nonprivileged(task_def) {
	container_defs := json.unmarshal(task_def.container_definitions)
	container := container_defs[_]
	is_nonprivileged(container)
}

# Allow task definitions with non-privileged containers
policy[p] {
	task_def := task_definitions[_]
	all_containers_nonprivileged(task_def)
	p = fugue.allow_resource(task_def)
}

# Deny task definitions with privileged containers
policy[p] {
	task_def := task_definitions[_]
	not all_containers_nonprivileged(task_def)
	p = fugue.deny_resource_with_message(
		task_def,
		"ECS task definition contains containers running in privileged mode. Remove privileged access for better security.",
	)
}
