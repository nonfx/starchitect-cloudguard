package rules.aws_batch_cloudwatch_logs

import data.fugue

__rego__metadoc__ := {
	"id": "5.1",
	"title": "Ensure AWS Batch is configured with AWS CloudWatch Logs",
	"description": "You can configure Batch jobs to send log information to CloudWatch Logs.",
	"custom": {
		"severity": "Medium",
		"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_5.1"]},
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

batch_job_definitions := fugue.resources("aws_batch_job_definition")

has_cloudwatch_logs(job_def) {
	container_properties := json.unmarshal(job_def.container_properties)
	log_configuration := container_properties.logConfiguration
	log_configuration.logDriver == "awslogs"
}

policy[p] {
	job_def := batch_job_definitions[_]
	has_cloudwatch_logs(job_def)
	p = fugue.allow_resource(job_def)
}

policy[p] {
	job_def := batch_job_definitions[_]
	not has_cloudwatch_logs(job_def)
	msg := sprintf("AWS Batch job definition '%s' is not configured to use CloudWatch Logs", [job_def.name])
	p = fugue.deny_resource_with_message(job_def, msg)
}
