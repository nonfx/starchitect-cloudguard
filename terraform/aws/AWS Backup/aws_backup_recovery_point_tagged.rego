package rules.aws_backup_recovery_point_tagged

import data.fugue
import future.keywords.in

__rego__metadoc__ := {
	"id": "Backup.2",
	"title": "AWS Backup recovery points should be tagged",
	"description": "This control checks whether an AWS Backup recovery point has any user-defined tags. The control fails if the recovery point doesn't have any user-defined tags. System tags, which are automatically applied and begin with aws:, are ignored.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Backup.2"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

backup_selections := fugue.resources("aws_backup_selection")

backup_plans := fugue.resources("aws_backup_plan")

has_user_tags(resource) {
	some key, _ in resource.tags
	not startswith(key, "aws:")
}

policy[p] {
	resource := backup_selections[_]
	has_user_tags(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := backup_selections[_]
	not has_user_tags(resource)
	p = fugue.deny_resource_with_message(resource, "AWS Backup selection has no user-defined tags")
}

policy[p] {
	resource := backup_plans[_]
	has_user_tags(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := backup_plans[_]
	not has_user_tags(resource)
	p = fugue.deny_resource_with_message(resource, "AWS Backup plan has no user-defined tags")
}
