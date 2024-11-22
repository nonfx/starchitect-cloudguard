package rules.ecs_task_definition_logging_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "ECS.9",
	"title": "ECS task definitions should have a logging configuration",
	"description": "ECS task definitions must include logging configuration to maintain visibility and debugging capabilities for container applications.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_ECS.9"]}, "severity": "High", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

task_definitions = fugue.resources("aws_ecs_task_definition")

# Helper function to check if container has valid logging configuration
has_valid_logging(container) {
	container.logConfiguration.logDriver != null
}

# Helper function to check if all containers in task definition have logging
all_containers_have_logging(task_def) {
	container_defs := json.unmarshal(task_def.container_definitions)
	container := container_defs[_]
	has_valid_logging(container)
}

policy[p] {
	task_def := task_definitions[_]
	all_containers_have_logging(task_def)
	p = fugue.allow_resource(task_def)
}

policy[p] {
	task_def := task_definitions[_]
	not all_containers_have_logging(task_def)
	p = fugue.deny_resource_with_message(task_def, "ECS task definition must have logging configuration for all containers")
}
