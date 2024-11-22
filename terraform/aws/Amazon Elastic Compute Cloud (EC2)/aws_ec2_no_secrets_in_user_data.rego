package rules.aws_ec2_no_secrets_in_user_data

import data.fugue
import future.keywords.in

__rego__metadoc__ := {
	"id": "2.13",
	"title": "Ensure Secrets and Sensitive Data are not stored directly in EC2 User Data",
	"description": "User Data can be specified when launching an ec2 instance. Examples include specifying parameters for configuring the instance or including a simple script.",
	"custom": {
		"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.13"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

ec2_instances := fugue.resources("aws_instance")

# List of keywords that might indicate sensitive information
sensitive_keywords = [
	"password",
	"secret",
	"key",
	"token",
	"credential",
	"api_key",
	"access_key",
	"private_key",
]

# Function to check if user data contains sensitive information
contains_sensitive_info(instance) {
	user_data = instance.user_data
	lower_data := lower(user_data)
	keyword := sensitive_keywords[_]
	contains(lower_data, keyword)
}

is_user_data_empty(instance) {
	user_data := instance.user_data
	user_data != null
}

policy[p] {
	instance := ec2_instances[_]
	is_user_data_empty(instance)
	contains_sensitive_info(instance)
	p := fugue.deny_resource(instance)
}

policy[p] {
	instance := ec2_instances[_]
	not is_user_data_empty(instance)
	p := fugue.allow_resource(instance)
}

policy[p] {
	instance := ec2_instances[_]
	is_user_data_empty(instance)
	not contains_sensitive_info(instance)
	p := fugue.allow_resource(instance)
}
