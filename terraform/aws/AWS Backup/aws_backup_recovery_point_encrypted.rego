package rules.aws_backup_recovery_point_encrypted

import data.fugue

__rego__metadoc__ := {
	"author": "sachin@nonfx.com",
	"id": "Backup.1",
	"title": "AWS Backup recovery points should be encrypted at rest",
	"description": "This control checks if an AWS Backup recovery point is encrypted at rest. The control fails if the recovery point isn't encrypted at rest. An AWS Backup recovery point refers to a specific copy or snapshot of data that is created as part of a backup process. It represents a particular moment in time when the data was backed up and serves as a restore point in case the original data becomes lost, corrupted, or inaccessible. Encrypting the backup recovery points adds an extra layer of protection against unauthorized access. Encryption is a best practice to protect the confidentiality, integrity, and security of backup data.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Backup.1"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

backup_plans := fugue.resources("aws_backup_plan")

backup_vaults := fugue.resources("aws_backup_vault")

is_valid(plan) {
	rule := plan.rule[_]
	rule.lifecycle[_].delete_after > 0
	rule.target_vault_name != ""
	rule.enable_continuous_backup == true
}

policy[p] {
	plan := backup_plans[_]
	is_valid(plan)
	vault := backup_vaults[_]
	vault.kms_key_arn != ""
	p = fugue.allow_resource(vault)
}

policy[p] {
	plan := backup_plans[_]
	is_valid(plan)
	vault := backup_vaults[_]
	vault.kms_key_arn == ""
	msg := sprintf("AWS Backup recovery vault %s is not encrypted.", [vault])
	p = fugue.deny_resource_with_message(vault, msg)
}

policy[p] {
	plan := backup_plans[_]
	not is_valid(plan)
	p = fugue.deny_resource_with_message(plan, "AWS Backup recovery plan is not valid.")
}
