package rules.cloudfront_default_root_object

import data.fugue

__rego__metadoc__ := {
	"id": "CloudFront.1",
	"title": "CloudFront distributions should have a default root object configured",
	"description": "This control checks whether an Amazon CloudFront distribution is configured to return a specific object that is the default root object. The control fails if the CloudFront distribution does not have a default root object configured. A user might sometimes request the distribution's root URL instead of an object in the distribution. When this happens, specifying a default root object can help you to avoid exposing the contents of your web distribution.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.1"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

cloudfront_distributions = fugue.resources("aws_cloudfront_distribution")

default_root_object_configured(resource) {
	resource.default_root_object != ""
}

policy[p] {
	resource := cloudfront_distributions[_]
	default_root_object_configured(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := cloudfront_distributions[_]
	not default_root_object_configured(resource)
	p = fugue.deny_resource_with_message(resource, "CloudFront distribution does not have a default root object configured")
}
