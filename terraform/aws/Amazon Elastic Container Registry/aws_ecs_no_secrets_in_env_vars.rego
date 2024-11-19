package rules.ecs_no_secrets_in_env_vars

import data.fugue

__rego__metadoc__ := {
	"id": "ECS.8",
	"title": "Secrets should not be passed as container environment variables",
	"description": "ECS task definitions should avoid passing secrets as environment variables and instead use AWS Systems Manager Parameter Store for secure credential management.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_ECS.8"]}, "severity": "High", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

task_definitions = fugue.resources("aws_ecs_task_definition")

# List of sensitive environment variable names to check
sensitive_env_vars = [
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"ECS_ENGINE_AUTH_DATA",
	"PASSWORD",
	"SECRET",
	"KEY",
]

# Helper function to check if container definitions contain sensitive env vars
has_sensitive_env_vars(container_definitions) {
	definition := container_definitions[_]
	env := definition.environment[_]
	contains(lower(env.name), lower(sensitive_env_vars[_]))
}

# Helper function to check if value looks like a secret
is_sensitive_value(value) {
	# Check for typical AWS access key format
	regex.match(`^(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}$`, value)
}

# Check for sensitive values in environment variables
has_sensitive_values(container_definitions) {
	definition := container_definitions[_]
	env := definition.environment[_]
	is_sensitive_value(env.value)
}

policy[p] {
	task_def := task_definitions[_]
	container_defs := json.unmarshal(task_def.container_definitions)
	has_sensitive_env_vars(container_defs)
	p = fugue.deny_resource_with_message(
		task_def,
		"Task definition contains sensitive information in environment variables",
	)
}

policy[p] {
	task_def := task_definitions[_]
	container_defs := json.unmarshal(task_def.container_definitions)
	has_sensitive_values(container_defs)
	p = fugue.deny_resource_with_message(
		task_def,
		"Task definition contains sensitive values in environment variables",
	)
}

policy[p] {
	task_def := task_definitions[_]
	container_defs := json.unmarshal(task_def.container_definitions)
	not has_sensitive_env_vars(container_defs)
	not has_sensitive_values(container_defs)
	p = fugue.allow_resource(task_def)
}
