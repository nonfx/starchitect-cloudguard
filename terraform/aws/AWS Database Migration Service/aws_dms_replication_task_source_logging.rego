package rules.dms_replication_task_logging

import data.fugue

__rego__metadoc__ := {
	"id": "DMS.8",
	"title": "DMS replication tasks for the source database should have logging enabled",
	"description": "This control checks whether AWS Database Migration Service (DMS) replication tasks have logging enabled with appropriate severity levels for source database operations.",
	"custom": {"severity":"Medium","controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_DMS.8"]},"author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

dms_tasks = fugue.resources("aws_dms_replication_task")

# Helper function to validate logging configuration
valid_logging_config(task) {
	logging := json.unmarshal(task.replication_task_settings)
	logging.Logging.EnableLogging == true
	logging.Logging.LogComponents[_].Id == "SOURCE_CAPTURE"
	logging.Logging.LogComponents[_].Id == "SOURCE_UNLOAD"
	logging.Logging.LogComponents[_].Severity == "LOGGER_SEVERITY_DEFAULT"
}

policy[p] {
	task := dms_tasks[_]
	valid_logging_config(task)
	p = fugue.allow_resource(task)
}

policy[p] {
	task := dms_tasks[_]
	not valid_logging_config(task)
	p = fugue.deny_resource_with_message(task, "DMS replication task must have logging enabled with LOGGER_SEVERITY_DEFAULT for SOURCE_CAPTURE and SOURCE_UNLOAD components")
}
