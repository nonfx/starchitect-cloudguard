package rules.aws_ec2_imdsv2

import data.fugue

__rego__metadoc__ := {
	"id": "5.6",
	"title": "Ensure that EC2 Metadata Service only allows IMDSv2",
	"description": "When enabling the Metadata Service on AWS EC2 instances, users have the option of using either Instance Metadata Service Version 1 (IMDSv1; a request/response method) or Instance Metadata Service Version 2 (IMDSv2; a session-oriented method).",
	"custom": {"controls":{"CIS-AWS-Foundations-Benchmark_v3.0.0":["CIS-AWS-Foundations-Benchmark_v3.0.0_5.6"]},"author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

instances := fugue.resources("aws_instance")

correct_metadata_options(instance) {
	metadata = instance.metadata_options[_]
	metadata.http_endpoint == "enabled"
	metadata.http_tokens == "required"
}

fail_metadata_options(instance) {
	metadata = instance.metadata_options[_]
	metadata.http_endpoint == "enabled"
	metadata.http_tokens == "optional"
}

fail_metadata_options(instance) {
	metadata = instance.metadata_options[_]
	metadata.http_endpoint == "enabled"
	not metadata.http_tokens
}

policy[p] {
	instance := instances[_]
	instance_id := instance.id
	fail_metadata_options(instance)
	msg := sprintf("AWS EC2 instance '%s' does not have IMDSv2 configured. Ensure http_endpoint is set to 'disabled' and http_tokens is set to 'required'.", [instance_id])
	p = fugue.deny_resource_with_message(instance, msg)
}

policy[p] {
	instance := instances[_]
	correct_metadata_options(instance)
	p = fugue.allow_resource(instance)
}
