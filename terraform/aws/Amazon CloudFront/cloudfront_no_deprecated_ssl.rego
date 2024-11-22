package rules.cloudfront_no_deprecated_ssl

import data.fugue

__rego__metadoc__ := {
	"id": "CloudFront.10",
	"title": "CloudFront distributions should not use deprecated SSL protocols between edge locations and custom origins",
	"description": "This control checks if Amazon CloudFront distributions are using deprecated SSL protocols for HTTPS communication between CloudFront edge locations and your custom origins. This control fails if a CloudFront distribution has a CustomOriginConfig where OriginSslProtocols includes SSLv3. In 2015, the Internet Engineering Task Force (IETF) officially announced that SSL 3.0 should be deprecated due to the protocol being insufficiently secure. It is recommended that you use TLSv1.2 or later for HTTPS communication to your custom origins",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.10"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

cloudfront_distributions = fugue.resources("aws_cloudfront_distribution")

deprecated_protocols := ["SSLv3", "TLSv1"]

no_deprecated_ssl(resource) {
	origin := resource.origin[_]
	custom_origin_config := origin.custom_origin_config[_]
	ssl_protocols := custom_origin_config.origin_ssl_protocols
	count([p | p = ssl_protocols[_]; p == deprecated_protocols[_]]) == 0
}

policy[p] {
	resource := cloudfront_distributions[_]
	no_deprecated_ssl(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := cloudfront_distributions[_]
	not no_deprecated_ssl(resource)
	p = fugue.deny_resource_with_message(resource, "CloudFront distribution is using deprecated SSL protocol (SSLv3) for communication with custom origins")
}
