package rules.ecs_container_readonly_root

import data.fugue

__rego__metadoc__ := {
	"id": "ECS.5",
	"title": "ECS containers should be limited to read-only access to root filesystems",
	"description": "This control checks if ECS containers are configured with read-only root filesystem access to prevent unauthorized modifications and enhance security.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_ECS.5"]}, "severity": "High", "author": "llmagent", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

# Get all ECS task definitions
task_definitions = fugue.resources("aws_ecs_task_definition")

# Helper to check if container has read-only root filesystem
has_readonly_root(container) {
	container.readonlyRootFilesystem == true
}

# Helper to check all containers in task definition
all_containers_readonly(task_def) {
	container_defs := json.unmarshal(task_def.container_definitions)
	count([container | container := container_defs[_]; not has_readonly_root(container)]) == 0
}

# Allow task definitions with read-only root filesystem
policy[p] {
	task_def := task_definitions[_]
	all_containers_readonly(task_def)
	p = fugue.allow_resource(task_def)
}

# Deny task definitions without read-only root filesystem
policy[p] {
	task_def := task_definitions[_]
	not all_containers_readonly(task_def)
	p = fugue.deny_resource_with_message(
		task_def,
		"ECS task definition contains containers without read-only root filesystem access. Set readonlyRootFilesystem to true for all containers.",
	)
}
