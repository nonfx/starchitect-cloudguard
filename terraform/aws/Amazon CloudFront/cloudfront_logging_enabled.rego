package rules.cloudfront_logging_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "CloudFront.5",
	"title": "CloudFront distributions should have logging enabled",
	"description": "This control checks whether server access logging is enabled on CloudFront distributions. The control fails if access logging is not enabled for a distribution. CloudFront access logs provide detailed information about every user request that CloudFront receives. Each log contains information such as the date and time the request was received, the IP address of the viewer that made the request, the source of the request, and the port number of the request from the viewer. These logs are useful for applications such as security and access audits and forensics investigation",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.5"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

cloudfront_distributions = fugue.resources("aws_cloudfront_distribution")

logging_enabled(resource) {
	logging_config := resource.logging_config[_]
	logging_config.bucket != ""
}

policy[p] {
	resource := cloudfront_distributions[_]
	logging_enabled(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := cloudfront_distributions[_]
	not logging_enabled(resource)
	p = fugue.deny_resource_with_message(resource, "CloudFront distribution does not have logging enabled")
}
