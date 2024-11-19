package rules.glue_job_logging_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "Glue.2",
	"title": "AWS Glue jobs should have logging enabled",
	"description": "AWS Glue jobs must have logging enabled to track system activities, detect security breaches, and maintain compliance requirements.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Glue.2"]}, "severity": "Medium", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

glue_jobs = fugue.resources("aws_glue_job")

# Helper function to check if logging is enabled
has_logging_enabled(job) {
	job.default_arguments["--enable-continuous-cloudwatch-log"] == "true"
}

# Allow jobs with logging enabled
policy[p] {
	job := glue_jobs[_]
	has_logging_enabled(job)
	p = fugue.allow_resource(job)
}

# Deny jobs without logging enabled
policy[p] {
	job := glue_jobs[_]
	not has_logging_enabled(job)
	p = fugue.deny_resource_with_message(job, "AWS Glue job must have continuous CloudWatch logging enabled")
}
