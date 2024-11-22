package rules.rds_cloudwatch_logs_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.9",
	"title": "RDS DB instances should publish logs to CloudWatch Logs",
	"description": "This control checks if RDS DB instances are configured to publish logs to CloudWatch Logs for monitoring and auditing purposes.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.9"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

db_instances = fugue.resources("aws_db_instance")

# Define required log types per engine
required_logs := {
	"oracle-ee": ["alert", "audit", "trace", "listener"],
	"oracle-se2": ["alert", "audit", "trace", "listener"],
	"postgres": ["postgresql", "upgrade"],
	"mysql": ["audit", "error", "general", "slowquery"],
	"mariadb": ["audit", "error", "general", "slowquery"],
	"sqlserver-ee": ["error", "agent"],
	"sqlserver-se": ["error", "agent"],
	"sqlserver-ex": ["error", "agent"],
	"sqlserver-web": ["error", "agent"],
}

# Check if engine is supported
is_supported_engine(engine) {
	required_logs[engine]
}

# Check if all required logs are enabled for the engine
has_required_logs(instance) {
	engine := lower(instance.engine)
	is_supported_engine(engine)
	required := required_logs[engine]
	enabled := {log | log := instance.enabled_cloudwatch_logs_exports[_]}
	missing := {log | log := required[_]; not enabled[log]}
	count(missing) == 0
}

# Allow instances with required logs enabled or unsupported engines
policy[p] {
	instance := db_instances[_]
	engine := lower(instance.engine)
	not is_supported_engine(engine)
	p = fugue.allow_resource(instance)
}

policy[p] {
	instance := db_instances[_]
	has_required_logs(instance)
	p = fugue.allow_resource(instance)
}

# Deny instances without required logs
policy[p] {
	instance := db_instances[_]
	engine := lower(instance.engine)
	is_supported_engine(engine)
	not has_required_logs(instance)
	required := required_logs[engine]
	p = fugue.deny_resource_with_message(
		instance,
		sprintf(
			"RDS instance with engine '%v' must publish the following logs to CloudWatch: %v",
			[engine, required],
		),
	)
}
