package rules.aws_datasync_task_logging_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "DataSync.1",
	"title": "DataSync tasks should have logging enabled",
	"description": "AWS DataSync tasks must have logging enabled to track system activities, enhance accountability, and maintain security compliance.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_DataSync.1"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

datasync_tasks = fugue.resources("aws_datasync_task")

# Helper function to check if logging is enabled
is_logging_enabled(task) {
	task.cloudwatch_log_group_arn != null
	task.cloudwatch_log_group_arn != ""
}

# Policy rule for allowing tasks with logging enabled
policy[p] {
	task := datasync_tasks[_]
	is_logging_enabled(task)
	p = fugue.allow_resource(task)
}

# Policy rule for denying tasks without logging
policy[p] {
	task := datasync_tasks[_]
	not is_logging_enabled(task)
	p = fugue.deny_resource_with_message(
		task,
		"DataSync task must have CloudWatch logging enabled",
	)
}
