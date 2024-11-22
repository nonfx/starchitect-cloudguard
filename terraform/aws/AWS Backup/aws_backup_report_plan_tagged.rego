package rules.aws_backup_report_plan_tagged

import data.fugue
import future.keywords.in

__rego__metadoc__ := {
	"id": "Backup.4",
	"title": "AWS Backup report plans should be tagged",
	"description": "This control checks whether an AWS Backup report plan has user-defined tags. The control fails if the report plan doesn't have any user-defined tag keys. System tags, which are automatically applied and begin with aws:, are ignored.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_Backup.4"]},"severity":"Low","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

backup_report_plans := fugue.resources("aws_backup_report_plan")

has_user_tags(resource) {
	some key, _ in resource.tags
	not startswith(key, "aws:")
}

policy[p] {
	resource := backup_report_plans[_]
	has_user_tags(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := backup_report_plans[_]
	not has_user_tags(resource)
	msg := sprintf("Backup report plan '%s' does not have any user-defined tags", [resource.name])
	p = fugue.deny_resource_with_message(resource, msg)
}
