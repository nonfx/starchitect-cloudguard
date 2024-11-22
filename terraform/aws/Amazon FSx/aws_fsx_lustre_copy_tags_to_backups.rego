package rules.fsx_lustre_copy_tags_to_backups

import data.fugue

__rego__metadoc__ := {
	"id": "FSx.2",
	"title": "FSx for Lustre file systems should be configured to copy tags to backups",
	"description": "FSx for Lustre file systems must be configured to automatically copy resource tags to their backup snapshots for proper resource tracking.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_FSx.2"]}, "severity": "Low"},
}

resource_type := "MULTIPLE"

# Get all FSx Lustre file systems
fsx_lustre_systems = fugue.resources("aws_fsx_lustre_file_system")

# Helper to check if copy tags to backups is enabled
has_copy_tags_to_backups(system) {
	system.copy_tags_to_backups == true
}

# Allow FSx Lustre systems with copy tags to backups enabled
policy[p] {
	system := fsx_lustre_systems[_]
	has_copy_tags_to_backups(system)
	p = fugue.allow_resource(system)
}

# Deny FSx Lustre systems without copy tags to backups enabled
policy[p] {
	system := fsx_lustre_systems[_]
	not has_copy_tags_to_backups(system)
	p = fugue.deny_resource_with_message(system, "FSx Lustre file system must be configured to copy tags to backups")
}
