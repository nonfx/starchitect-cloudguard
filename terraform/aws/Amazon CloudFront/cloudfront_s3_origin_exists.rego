package rules.cloudfront_s3_origin_exists

import data.fugue

__rego__metadoc__ := {
	"id": "CloudFront.12",
	"title": "CloudFront distributions should not point to non-existent S3 origins",
	"description": "This control checks whether Amazon CloudFront distributions are pointing to non-existent Amazon S3 origins. The control fails for a CloudFront distribution if the origin is configured to point to a non-existent bucket. This control only applies to CloudFront distributions where an S3 bucket without static website hosting is the S3 origin. When a CloudFront distribution in your account is configured to point to a non-existent bucket, a malicious third party can create the referenced bucket and serve their own content through your distribution. We recommend checking all origins regardless of routing behavior to ensure that your distributions are pointing to appropriate origins.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.12"]},
		"severity": "Critical",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

cloudfront_distributions = fugue.resources("aws_cloudfront_distribution")

s3_buckets = fugue.resources("aws_s3_bucket")

s3_origin_exists(resource) {
	origin := resource.origin[_]
	s3_origin_config := origin.s3_origin_config[_]
	bucket_name := regex.replace(origin.domain_name, "\\.s3\\..*", "")
	s3_buckets[bucket_name]
}

policy[p] {
	resource := cloudfront_distributions[_]
	s3_origin_exists(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := cloudfront_distributions[_]
	not s3_origin_exists(resource)
	p = fugue.deny_resource_with_message(resource, "CloudFront distribution is pointing to a non-existent S3 origin")
}
