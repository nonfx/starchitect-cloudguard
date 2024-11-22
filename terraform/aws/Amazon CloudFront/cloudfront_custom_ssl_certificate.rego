package rules.cloudfront_custom_ssl_certificate

import data.fugue

__rego__metadoc__ := {
	"id": "CloudFront.7",
	"title": "CloudFront distributions should use custom SSL/TLS certificates",
	"description": "This control checks whether CloudFront distributions are using the default SSL/TLS certificate CloudFront provides. This control passes if the CloudFront distribution uses a custom SSL/TLS certificate. This control fails if the CloudFront distribution uses the default SSL/TLS certificate. Custom SSL/TLS allow your users to access content by using alternate domain names. You can store custom certificates in AWS Certificate Manager (recommended), or in IAM",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.7"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

cloudfront_distributions = fugue.resources("aws_cloudfront_distribution")

custom_ssl_certificate_used(resource) {
	viewer_certificate := resource.viewer_certificate[_]
	not viewer_certificate.cloudfront_default_certificate
}

policy[p] {
	resource := cloudfront_distributions[_]
	custom_ssl_certificate_used(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := cloudfront_distributions[_]
	not custom_ssl_certificate_used(resource)
	p = fugue.deny_resource_with_message(resource, "CloudFront distribution is using the default SSL/TLS certificate instead of a custom certificate")
}
