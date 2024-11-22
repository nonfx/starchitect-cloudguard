package rules.cloudfront_sni_https

import data.fugue

__rego__metadoc__ := {
	"id": "CloudFront.8",
	"title": "CloudFront distributions should use SNI to serve HTTPS requests",
	"description": "This control checks if Amazon CloudFront distributions are using a custom SSL/TLS certificate and are configured to use SNI to serve HTTPS requests. This control fails if a custom SSL/TLS certificate is associated but the SSL/TLS support method is a dedicated IP address. Server Name Indication (SNI) is an extension to the TLS protocol that is supported by browsers and clients released after 2010. If you configure CloudFront to serve HTTPS requests using SNI, CloudFront associates your alternate domain name with an IP address for each edge location. When a viewer submits an HTTPS request for your content, DNS routes the request to the IP address for the correct edge location. The IP address to your domain name is determined during the SSL/TLS handshake negotiation; the IP address isn't dedicated to your distribution",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.8"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

cloudfront_distributions = fugue.resources("aws_cloudfront_distribution")

uses_sni(resource) {
	viewer_certificate := resource.viewer_certificate[_]
	not viewer_certificate.cloudfront_default_certificate
	viewer_certificate.ssl_support_method == "sni-only"
}

policy[p] {
	resource := cloudfront_distributions[_]
	uses_sni(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := cloudfront_distributions[_]
	not uses_sni(resource)
	p = fugue.deny_resource_with_message(resource, "CloudFront distribution is not configured to use SNI for HTTPS requests or is using a dedicated IP address instead of SNI")
}
