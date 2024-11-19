package rules.ecs_task_definition_security

import data.fugue
import future.keywords.in

__rego__metadoc__ := {
	"id": "ECS.1",
	"title": "Amazon ECS task definitions should have secure networking modes and user definitions",
	"description": "This control checks if ECS task definitions use secure networking modes and user definitions to prevent privilege escalation and unauthorized access.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_ECS.1"]}, "severity": "High", "author": "llmagent"},
}

resource_type := "MULTIPLE"

# Get all ECS task definitions
task_definitions = fugue.resources("aws_ecs_task_definition")

# Helper function to check container definition security
is_secure_container(container_def) {
	parsed := json.unmarshal(container_def)
	some i
	container := parsed[i]

	# Check for non-root user
	container.user != null
	container.user != ""
	container.user != "root"

	# Check privileged mode is explicitly false
	container.privileged == false
}

# Allow task definitions that meet security requirements
policy[p] {
	task := task_definitions[_]
	task.network_mode == "host"
	is_secure_container(task.container_definitions)
	p = fugue.allow_resource(task)
}

# Allow task definitions not using host network mode
policy[p] {
	task := task_definitions[_]
	task.network_mode != "host"
	p = fugue.allow_resource(task)
}

# Deny insecure task definitions
policy[p] {
	task := task_definitions[_]
	task.network_mode == "host"
	not is_secure_container(task.container_definitions)
	p = fugue.deny_resource_with_message(
		task,
		"ECS task definitions using host network mode must use non-root users and explicitly set privileged=false",
	)
}
