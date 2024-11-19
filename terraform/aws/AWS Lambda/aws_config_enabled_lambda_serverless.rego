package rules.aws_config_enabled_lambda_serverless

import data.fugue

__rego__metadoc__ := {
	"author": "sachin@nonfx.com",
	"id": "4.1",
	"title": "Ensure AWS Config is Enabled for Lambda and Serverless",
	"description": "With AWS Config, you can track configuration changes to the Lambda functions (including deleted functions), runtime environments, tags, handler name, code size, memory allocation, timeout settings, and concurrency settings, along with Lambda IAM execution role, subnet, and security group associations",
	"custom": {
		"severity": "Medium",
		"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_4.1"]},
	},
}

resource_type := "MULTIPLE"

config_recorders := fugue.resources("aws_config_configuration_recorder")

config_recorder_status := fugue.resources("aws_config_configuration_recorder_status")

# Check if AWS Config is enabled and recording all resources
config_enabled_and_recording(recorder, status) {
	recorder.recording_group[_].all_supported
	recorder.recording_group[_].include_global_resource_types
	status.is_enabled
}

any_match(arr, str) {
	some i
	arr[i] == str
}

# Check if Lambda resources are included in the recording
lambda_included(recorder) {
	any_match(recorder.recording_group[_].resource_types, "AWS::Lambda::Function")
}

policy[p] {
	recorder := config_recorders[_]
	status := config_recorder_status[_]
	config_enabled_and_recording(recorder, status)
	lambda_included(recorder)
	p = fugue.allow_resource(recorder)
}

policy[p] {
	recorder := config_recorders[_]
	status := config_recorder_status[_]
	not config_enabled_and_recording(recorder, status)
	msg := "AWS Config is not enabled or not recording all resources."
	p = fugue.deny_resource_with_message(recorder, msg)
}

policy[p] {
	recorder := config_recorders[_]
	not lambda_included(recorder)
	msg := "AWS Config is not configured to record Lambda function resources."
	p = fugue.deny_resource_with_message(recorder, msg)
}
