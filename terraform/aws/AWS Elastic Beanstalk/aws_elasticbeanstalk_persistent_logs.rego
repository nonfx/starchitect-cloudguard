package rules.aws_elasticbeanstalk_persistent_logs

import data.fugue

__rego__metadoc__ := {
	"id": "6.2",
	"title": "Ensure Persistent logs is setup and configured to S3",
	"description": "Elastic Beanstalk can be configured to automatically stream logs to the CloudWatch service. With CloudWatch Logs, you can monitor and archive your Elastic Beanstalk application, system, and custom log files from Amazon EC2 instances of your environments.",
	"custom": {"controls":{"CIS-AWS-Compute-Services-Benchmark_v1.0.0":["CIS-AWS-Compute-Services-Benchmark_v1.0.0_6.2"]},"author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

beanstalk_env := fugue.resources("aws_elastic_beanstalk_environment")

log_streaming_enabled(environment) {
	option := environment.setting[_]
	option.namespace == "aws:elasticbeanstalk:cloudwatch:logs"
	option.name == "StreamLogs"
	option.value == "true"
}

retention_configured(environment) {
	option := environment.setting[_]
	option.namespace == "aws:elasticbeanstalk:cloudwatch:logs"
	option.name == "RetentionInDays"
	to_number(option.value) > 0
}

logs_kept_after_termination(environment) {
	option := environment.setting[_]
	option.namespace == "aws:elasticbeanstalk:cloudwatch:logs"
	option.name == "DeleteOnTerminate"
	option.value == "false"
}

policy[p] {
	environment := beanstalk_env[_]
	log_streaming_enabled(environment)
	retention_configured(environment)
	logs_kept_after_termination(environment)
	p := fugue.allow_resource(environment)
}

policy[p] {
	environment := beanstalk_env[_]
	not log_streaming_enabled(environment)
	p := fugue.deny_resource_with_message(environment, "Log streaming is not enabled for this Elastic Beanstalk environment")
}

policy[p] {
	environment := beanstalk_env[_]
	log_streaming_enabled(environment)
	not retention_configured(environment)
	p := fugue.deny_resource_with_message(environment, "Log retention period is not configured for this Elastic Beanstalk environment")
}

policy[p] {
	environment := beanstalk_env[_]
	log_streaming_enabled(environment)
	not logs_kept_after_termination(environment)
	p := fugue.deny_resource_with_message(environment, "Logs are not configured to be kept after environment termination")
}
