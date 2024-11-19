package rules.cloudfront_origin_failover

import data.fugue

__rego__metadoc__ := {
	"author": "sachin@nonfx.com",
	"id": "CloudFront.4",
	"title": "CloudFront distributions should have origin failover configured",
	"description": "This control checks whether an Amazon CloudFront distribution is configured with an origin group that has two or more origins. CloudFront origin failover can increase availability. Origin failover automatically redirects traffic to a secondary origin if the primary origin is unavailable or if it returns specific HTTP response status codes.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.4"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

cloudfront_distributions = fugue.resources("aws_cloudfront_distribution")

has_origin_failover(resource) {
	origin_group := resource.origin_group[_]
	count(origin_group.member) >= 2
}

policy[p] {
	resource := cloudfront_distributions[_]
	has_origin_failover(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := cloudfront_distributions[_]
	not has_origin_failover(resource)
	p = fugue.deny_resource_with_message(resource, "CloudFront distribution does not have origin failover configured with at least two origins")
}
