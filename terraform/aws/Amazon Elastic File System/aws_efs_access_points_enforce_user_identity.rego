package rules.efs_access_points_enforce_user_identity

import data.fugue

__rego__metadoc__ := {
	"id": "EFS.4",
	"title": "EFS access points should enforce a user identity",
	"description": "EFS access points must enforce user identity by defining POSIX user identity during creation for secure application access management.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_EFS.4"]}, "severity": "Medium"},
}

resource_type := "MULTIPLE"

# Get all EFS access points
efs_access_points = fugue.resources("aws_efs_access_point")

# Helper function to check if POSIX user identity is properly configured
has_valid_posix_user(access_point) {
	user := access_point.posix_user[_]
	user.uid != null
	user.gid != null
}

# Allow rule for compliant access points
policy[p] {
	access_point := efs_access_points[_]
	has_valid_posix_user(access_point)
	p = fugue.allow_resource(access_point)
}

# Deny rule for non-compliant access points
policy[p] {
	access_point := efs_access_points[_]
	not has_valid_posix_user(access_point)
	p = fugue.deny_resource_with_message(access_point, "EFS access point must enforce user identity by configuring POSIX user with UID and GID")
}
