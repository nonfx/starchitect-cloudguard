package rules.efs_mount_targets_not_public

import data.fugue

__rego__metadoc__ := {
	"id": "EFS.6",
	"title": "EFS mount targets should not be associated with a public subnet",
	"description": "This control checks if EFS mount targets are associated with private subnets to prevent unauthorized access from the internet.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_EFS.6"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all EFS mount targets and subnets
efs_mount_targets = fugue.resources("aws_efs_mount_target")

subnets = fugue.resources("aws_subnet")

# Helper function to check if a subnet is public
is_public_subnet(subnet) {
	subnet.map_public_ip_on_launch == true
}

# Helper function to check if mount target is in public subnet
is_mount_target_public(mount_target) {
	subnet := subnets[_]
	subnet.id == mount_target.subnet_id
	is_public_subnet(subnet)
}

# Allow mount targets in private subnets
policy[p] {
	mount_target := efs_mount_targets[_]
	not is_mount_target_public(mount_target)
	p = fugue.allow_resource(mount_target)
}

# Deny mount targets in public subnets
policy[p] {
	mount_target := efs_mount_targets[_]
	is_mount_target_public(mount_target)
	p = fugue.deny_resource_with_message(mount_target, "EFS mount target should not be associated with a public subnet")
}
