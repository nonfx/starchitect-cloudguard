package rules.s3_access_point_block_public_access

import data.fugue

__rego__metadoc__ := {
	"id": "S3.19",
	"title": "S3 access points should have block public access settings enabled",
	"description": "S3 access points must have block public access settings enabled to prevent unauthorized access and maintain security. All block public access settings should be enabled by default for new access points and cannot be changed after creation.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_S3.19"]}, "severity": "High", "author": "llmagent"},
}

# Define resource type for multiple resources
resource_type := "MULTIPLE"

# Get all S3 access points
access_points = fugue.resources("aws_s3_access_point")

# Helper function to check if all block public access settings are enabled
is_block_public_access_enabled(ap) {
	config := ap.public_access_block_configuration[_]
	config.block_public_acls != false
	config.block_public_policy != false
	config.ignore_public_acls != false
	config.restrict_public_buckets != false
}

# Allow if all block public access settings are enabled
policy[p] {
	ap := access_points[_]
	is_block_public_access_enabled(ap)
	p = fugue.allow_resource(ap)
}

# Deny if any block public access setting is disabled or missing
policy[p] {
	ap := access_points[_]
	not is_block_public_access_enabled(ap)
	p = fugue.deny_resource_with_message(ap, "S3 access point must have all block public access settings enabled")
}
