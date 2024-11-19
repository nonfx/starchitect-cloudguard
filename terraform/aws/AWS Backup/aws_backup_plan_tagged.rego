package rules.aws_backup_plan_tagged

import data.fugue
import future.keywords.in

__rego__metadoc__ := {
	"author": "sachin@nonfx.com",
	"id": "Backup.5",
	"title": "AWS Backup backup plans should be tagged",
	"description": "This control checks whether an AWS Backup backup plan has user-defined tags. The control fails if the backup plan doesn't have any user-defined tag keys. System tags, which are automatically applied and begin with aws:, are ignored.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Backup.5"]},
		"severity": "Low",
	},
}

resource_type := "MULTIPLE"

backup_plans := fugue.resources("aws_backup_plan")

has_user_tags(resource) {
	some key, _ in resource.tags
	not startswith(key, "aws:")
}

policy[p] {
	resource := backup_plans[_]
	has_user_tags(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := backup_plans[_]
	not has_user_tags(resource)
	msg := sprintf("Backup plan '%s' does not have any user-defined tags", [resource.name])
	p = fugue.deny_resource_with_message(resource, msg)
}
