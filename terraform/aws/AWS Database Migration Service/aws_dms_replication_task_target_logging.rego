package rules.dms_replication_task_logging

import data.fugue

__rego__metadoc__ := {
	"id": "DMS.7",
	"title": "DMS replication tasks for the target database should have logging enabled",
	"description": "DMS replication tasks must have logging enabled with minimum severity level of LOGGER_SEVERITY_DEFAULT for target database operations.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_DMS.7"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Helper function to check if logging configuration is valid
has_valid_logging(task) {
	settings := json.unmarshal(task.replication_task_settings)
	settings.Logging.EnableLogging == true

	# Create a map of component IDs to their severity levels
	components := {c.Id: c.Severity | c := settings.Logging.LogComponents[_]}

	# Check both required components have DEFAULT severity
	components.TARGET_APPLY == "LOGGER_SEVERITY_DEFAULT"
	components.TARGET_LOAD == "LOGGER_SEVERITY_DEFAULT"
}

# Get all DMS replication tasks
dms_tasks = fugue.resources("aws_dms_replication_task")

# Allow resources that have valid logging configuration
policy[p] {
	task := dms_tasks[_]
	has_valid_logging(task)
	p = fugue.allow_resource(task)
}

# Deny resources that don't have valid logging configuration
policy[p] {
	task := dms_tasks[_]
	not has_valid_logging(task)
	p = fugue.deny_resource_with_message(
		task,
		"DMS replication task must have logging enabled with minimum severity level of LOGGER_SEVERITY_DEFAULT for target database operations",
	)
}
