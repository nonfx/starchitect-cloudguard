package rules.aws_workspaces_user_volume_encrypted

import data.fugue

__rego__metadoc__ := {
	"author": "ankit@nonfx.com",
	"id": "WorkSpaces.1",
	"title": "WorkSpaces user volumes should be encrypted at rest",
	"description": "This control checks whether a user volume in an Amazon WorkSpaces WorkSpace is encrypted at rest. The control fails if the WorkSpace user volume isn't encrypted at rest.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_WorkSpaces.1"]}},
}

resource_type := "MULTIPLE"

workspaces := fugue.resources("aws_workspaces_workspace")

is_user_volume_encrypted(workspace) {
	workspace.user_volume_encryption_enabled
}

policy[p] {
	workspace := workspaces[_]
	is_user_volume_encrypted(workspace)
	p = fugue.allow_resource(workspace)
}

policy[p] {
	workspace := workspaces[_]
	not is_user_volume_encrypted(workspace)
	p = fugue.deny_resource_with_message(workspace, "WorkSpace user volume is not encrypted at rest")
}
