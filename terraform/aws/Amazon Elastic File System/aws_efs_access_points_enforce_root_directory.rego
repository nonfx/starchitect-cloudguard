package rules.efs_access_points_enforce_root_directory

import data.fugue

__rego__metadoc__ := {
	"id": "EFS.3",
	"title": "EFS access points should enforce a root directory",
	"description": "EFS access points must enforce a root directory to restrict data access by ensuring users can only access specified subdirectory files.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_EFS.3"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

efs_access_points = fugue.resources("aws_efs_access_point")

# Helper function to check if root directory is properly enforced
is_root_directory_enforced(access_point) {
	access_point.root_directory[_].path != "/"
}

policy[p] {
	access_point := efs_access_points[_]
	is_root_directory_enforced(access_point)
	p = fugue.allow_resource(access_point)
}

policy[p] {
	access_point := efs_access_points[_]
	not is_root_directory_enforced(access_point)
	p = fugue.deny_resource_with_message(access_point, "EFS access point must enforce a root directory other than '/'")
}
