package rules.aws_rds_monitoring_and_logging_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "3.9",
	"title": "Ensure Monitoring and Logging is Enabled",
	"description": "Ensures that monitoring and logging are enabled for RDS instances to track activity and detect potential security issues.",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_3.9"]},"severity":"Low","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

aws_db_instances = fugue.resources("aws_db_instance")

# Check if monitoring is enabled
is_monitoring_enabled(instance) {
	instance.monitoring_interval > 0
	instance.monitoring_role_arn != ""
}

# Check if logging is enabled
is_logging_enabled(instance) {
	count(instance.enabled_cloudwatch_logs_exports) > 0
}

policy[p] {
	instance := aws_db_instances[_]
	is_monitoring_enabled(instance)
	is_logging_enabled(instance)
	p = fugue.allow_resource(instance)
}

policy[p] {
	instance := aws_db_instances[_]
	not is_monitoring_enabled(instance)
	msg := sprintf("RDS instance '%s' does not have monitoring enabled. Enable monitoring for this instance.", [instance.id])
	p = fugue.deny_resource_with_message(instance, msg)
}

policy[p] {
	instance := aws_db_instances[_]
	not is_logging_enabled(instance)
	msg := sprintf("RDS instance '%s' does not have logging enabled. Enable logging for this instance.", [instance.id])
	p = fugue.deny_resource_with_message(instance, msg)
}
