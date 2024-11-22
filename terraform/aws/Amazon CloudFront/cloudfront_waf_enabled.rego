package rules.cloudfront_waf_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "CloudFront.6",
	"title": "CloudFront distributions should have WAF enabled",
	"description": "This control checks whether CloudFront distributions are associated with either AWS WAF Classic or AWS WAF web ACLs. The control fails if the distribution is not associated with a web ACL. AWS WAF is a web application firewall that helps protect web applications and APIs from attacks. It allows you to configure a set of rules, called a web access control list (web ACL), that allow, block, or count web requests based on customizable web security rules and conditions that you define. Ensure your CloudFront distribution is associated with an AWS WAF web ACL to help protect it from malicious attacks",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.6"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

cloudfront_distributions = fugue.resources("aws_cloudfront_distribution")

waf_enabled(resource) {
	resource.web_acl_id != ""
}

policy[p] {
	resource := cloudfront_distributions[_]
	waf_enabled(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := cloudfront_distributions[_]
	not waf_enabled(resource)
	p = fugue.deny_resource_with_message(resource, "CloudFront distribution does not have WAF enabled")
}
