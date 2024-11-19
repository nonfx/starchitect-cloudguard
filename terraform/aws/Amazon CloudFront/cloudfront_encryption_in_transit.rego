package rules.cloudfront_encryption_in_transit

import data.fugue

__rego__metadoc__ := {
	"author": "sachin@nonfx.com",
	"id": "CloudFront.3",
	"title": "CloudFront distributions should require encryption in transit",
	"description": "This control checks whether an Amazon CloudFront distribution requires viewers to use HTTPS directly or whether it uses redirection. The control fails if ViewerProtocolPolicy is set to allow-all for defaultCacheBehavior or for cacheBehaviors. HTTPS (TLS) can be used to help prevent potential attackers from using person-in-the-middle or similar attacks to eavesdrop on or manipulate network traffic. Only encrypted connections over HTTPS (TLS) should be allowed. Encrypting data in transit can affect performance. You should test your application with this feature to understand the performance profile and the impact of TLS.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.3"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

cloudfront_distributions = fugue.resources("aws_cloudfront_distribution")

valid_viewer_protocol_policy(policy) {
	policy == "https-only"
}

valid_viewer_protocol_policy(policy) {
	policy == "redirect-to-https"
}

valid_distribution(resource) {
	valid_viewer_protocol_policy(resource.default_cache_behavior[_].viewer_protocol_policy)
	count(resource.ordered_cache_behavior) > 0
	cache_behaviors := resource.ordered_cache_behavior[_]
	valid_viewer_protocol_policy(cache_behaviors.viewer_protocol_policy)
}

valid_distribution(resource) {
	valid_viewer_protocol_policy(resource.default_cache_behavior[_].viewer_protocol_policy)
	count(resource.ordered_cache_behavior) == 0
}

policy[p] {
	resource := cloudfront_distributions[_]
	valid_distribution(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := cloudfront_distributions[_]
	not valid_distribution(resource)
	p = fugue.deny_resource_with_message(resource, "CloudFront distribution does not require encryption in transit for all cache behaviors")
}
