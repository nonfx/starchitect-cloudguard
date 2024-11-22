package rules.cloudfront_encrypt_traffic_to_custom_origins

import data.fugue

__rego__metadoc__ := {
	"id": "CloudFront.9",
	"title": "CloudFront distributions should encrypt traffic to custom origins",
	"description": "This control checks if Amazon CloudFront distributions are encrypting traffic to custom origins. This control fails for a CloudFront distribution whose origin protocol policy allows 'http-only'. This control also fails if the distribution's origin protocol policy is 'match-viewer' while the viewer protocol policy is 'allow-all'. HTTPS (TLS) can be used to help prevent eavesdropping or manipulation of network traffic. Only encrypted connections over HTTPS (TLS) should be allowed",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.9"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

cloudfront_distributions = fugue.resources("aws_cloudfront_distribution")

encrypts_traffic_to_custom_origin(resource) {
	origin := resource.origin[_]
	custom_origin_config := origin.custom_origin_config[_]
	custom_origin_config.origin_protocol_policy != "http-only"
	not match_viewer_and_allow_all(resource, custom_origin_config)
}

match_viewer_and_allow_all(resource, custom_origin_config) {
	custom_origin_config.origin_protocol_policy == "match-viewer"
	resource.default_cache_behavior[_].viewer_protocol_policy == "allow-all"
}

policy[p] {
	resource := cloudfront_distributions[_]
	encrypts_traffic_to_custom_origin(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := cloudfront_distributions[_]
	not encrypts_traffic_to_custom_origin(resource)
	p = fugue.deny_resource_with_message(resource, "CloudFront distribution is not encrypting traffic to custom origins or allows insecure protocols")
}
