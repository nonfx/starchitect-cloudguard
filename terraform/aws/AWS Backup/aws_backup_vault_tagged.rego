package rules.aws_backup_vault_tagged

import data.fugue
import future.keywords.in

__rego__metadoc__ := {
	"id": "Backup.3",
	"title": "AWS Backup vaults should be tagged",
	"description": "This control checks whether an AWS Backup vault has user-defined tags. The control fails if the backup vault doesn't have any user-defined tag keys. System tags, which are automatically applied and begin with aws:, are ignored.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_Backup.3"]},"severity":"Low","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

backup_vaults := fugue.resources("aws_backup_vault")

has_user_tags(resource) {
	some key, _ in resource.tags
	not startswith(key, "aws:")
}

policy[p] {
	resource := backup_vaults[_]
	has_user_tags(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := backup_vaults[_]
	not has_user_tags(resource)
	msg := sprintf("Backup vault '%s' does not have any user-defined tags", [resource.name])
	p = fugue.deny_resource_with_message(resource, msg)
}
