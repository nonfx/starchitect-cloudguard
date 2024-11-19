package rules.aws_workspaces_root_volume_encrypted

import data.fugue

__rego__metadoc__ := {
	"author": "ankit@nonfx.com",
	"id": "WorkSpaces.2",
	"title": "WorkSpaces root volumes should be encrypted at rest",
	"description": "This control checks whether a root volume in an Amazon WorkSpaces WorkSpace is encrypted at rest. The control fails if the WorkSpace root volume isn't encrypted at rest.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_WorkSpaces.2"]}},
}

resource_type := "MULTIPLE"

workspaces := fugue.resources("aws_workspaces_workspace")

is_root_volume_encrypted(workspace) {
	workspace.root_volume_encryption_enabled
}

policy[p] {
	workspace := workspaces[_]
	is_root_volume_encrypted(workspace)
	p = fugue.allow_resource(workspace)
}

policy[p] {
	workspace := workspaces[_]
	not is_root_volume_encrypted(workspace)
	p = fugue.deny_resource_with_message(workspace, "WorkSpace root volume is not encrypted at rest")
}
