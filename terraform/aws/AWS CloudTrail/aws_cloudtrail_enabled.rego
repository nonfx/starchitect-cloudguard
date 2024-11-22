package rules.aws_cloudtrail_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "CloudTrail.3",
	"title": "At least one CloudTrail trail should be enabled",
	"description": "This control checks whether an AWS CloudTrail trail is enabled in your AWS account. The control fails if your account doesn't have at least one CloudTrail trail enabled.However, some AWS services do not enable logging of all APIs and events. You should implement any additional audit trails other than CloudTrail and review the documentation for each service in CloudTrail Supported Services and Integrations",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudTrail.3"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

cloudtrails = fugue.resources("aws_cloudtrail")

policy[p] {
	count(cloudtrails) > 0
	enabled_trails := [trail | trail := cloudtrails[_]; trail.enable_logging == true]
	count(enabled_trails) > 0
	p = fugue.allow_resource(enabled_trails[0])
}

policy[p] {
	count(cloudtrails) == 0
	p = fugue.deny_resource_with_message(cloudtrails[0], "No CloudTrail trails found in the account")
}

policy[p] {
	count(cloudtrails) > 0
	enabled_trails := [trail | trail := cloudtrails[_]; trail.enable_logging == true]
	count(enabled_trails) == 0
	p = fugue.deny_resource_with_message(cloudtrails[0], "No enabled CloudTrail trails found in the account")
}

invalid_cloudtrail(trail) {
	trail.enable_logging != true
}

policy[p] {
	trail := cloudtrails[_]
	invalid_cloudtrail(trail)
	p = fugue.deny_resource_with_message(trail, sprintf("CloudTrail '%v' is not enabled", [trail.name]))
}
