package rules.ecs_task_definition_pid_mode

import data.fugue

__rego__metadoc__ := {
	"id": "ECS.3",
	"title": "ECS task definitions should not share the host's process namespace",
	"description": "This control checks if ECS task definitions share the host's process namespace with containers. Sharing the host's process namespace reduces process isolation and could allow unauthorized access to host system processes.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_ECS.3"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all ECS task definitions
task_definitions = fugue.resources("aws_ecs_task_definition")

# Helper to check if PID mode is secure
is_pid_mode_secure(task_def) {
	not task_def.pid_mode == "host"
}

is_pid_mode_secure(task_def) {
	not task_def.pid_mode
}

# Allow task definitions that don't share host PID namespace
policy[p] {
	task_def := task_definitions[_]
	is_pid_mode_secure(task_def)
	p = fugue.allow_resource(task_def)
}

# Deny task definitions that share host PID namespace
policy[p] {
	task_def := task_definitions[_]
	not is_pid_mode_secure(task_def)
	p = fugue.deny_resource_with_message(
		task_def,
		"ECS task definition shares host's process namespace. Configure pidMode to not use 'host' for better security isolation.",
	)
}
