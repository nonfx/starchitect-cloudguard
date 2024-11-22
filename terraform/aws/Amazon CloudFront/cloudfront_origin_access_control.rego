package rules.cloudfront_origin_access_control

import data.fugue

__rego__metadoc__ := {
	"id": "CloudFront.13",
	"title": "CloudFront distributions should use origin access control",
	"description": "This control checks whether an Amazon CloudFront distribution with an Amazon S3 origin has origin access control (OAC) configured. The control fails if OAC isn't configured for the CloudFront distribution. When using an S3 bucket as an origin for your CloudFront distribution, you can enable OAC. This permits access to the content in the bucket only through the specified CloudFront distribution, and prohibits access directly from the bucket or another distribution. Although CloudFront supports Origin Access Identity (OAI), OAC offers additional functionality, and distributions using OAI can migrate to OAC. While OAI provides a secure way to access S3 origins, it has limitations, such as lack of support for granular policy configurations and for HTTP/HTTPS requests that use the POST method in AWS Regions that require AWS Signature Version 4 (SigV4). OAI also doesn't support encryption with AWS Key Management Service. OAC is based on an AWS best practice of using IAM service principals to authenticate with S3 origins.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.13"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

cloudfront_distributions = fugue.resources("aws_cloudfront_distribution")

uses_origin_access_control(resource) {
	origin := resource.origin[_]
	origin.origin_access_control_id
}

policy[p] {
	resource := cloudfront_distributions[_]
	uses_origin_access_control(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := cloudfront_distributions[_]
	not uses_origin_access_control(resource)
	p = fugue.deny_resource_with_message(resource, "CloudFront distribution with S3 origin does not have origin access control configured")
}
