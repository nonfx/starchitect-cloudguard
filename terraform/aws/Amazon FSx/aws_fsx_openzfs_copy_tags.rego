package rules.fsx_openzfs_copy_tags

import data.fugue

__rego__metadoc__ := {
	"id": "FSx.1",
	"title": "FSx for OpenZFS file systems should be configured to copy tags to backups and volumes",
	"description": "FSx OpenZFS file systems must be configured to automatically copy tags to backups and volumes for proper resource tracking.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_FSx.1"]},"severity":"Low","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all FSx OpenZFS file systems
fsx_filesystems = fugue.resources("aws_fsx_openzfs_file_system")

# Helper to check if tag copying is enabled for both backups and volumes
tags_properly_copied(filesystem) {
	filesystem.copy_tags_to_backups == true
	filesystem.copy_tags_to_volumes == true
}

# Allow file systems with proper tag copying configuration
policy[p] {
	filesystem := fsx_filesystems[_]
	tags_properly_copied(filesystem)
	p = fugue.allow_resource(filesystem)
}

# Deny file systems without proper tag copying configuration
policy[p] {
	filesystem := fsx_filesystems[_]
	not tags_properly_copied(filesystem)
	p = fugue.deny_resource_with_message(filesystem, "FSx OpenZFS file system must be configured to copy tags to both backups and volumes")
}
