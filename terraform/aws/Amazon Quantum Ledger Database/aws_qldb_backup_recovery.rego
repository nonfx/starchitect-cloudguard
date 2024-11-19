package rules.aws_qldb_backup_recovery

import data.fugue

__rego__metadoc__ := {
	"author": "rajat@nonfx.com",
	"id": "11.7",
	"title": "Ensure to Enable Backup and Recovery",
	"description": "Having the data backed up ensures that all the crucial information is stored securely it defends against any human errors and system errors that resulted in data loss. An organization that has a disaster recovery plan is prepared for any disruption that would impact business operations",
	"custom": {
		"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_11.7"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

qldb_ledgers := fugue.resources("aws_qldb_ledger")

backup_enabled(ledger) {
	ledger.deletion_protection == true
	ledger.kms_key != null
}

policy[p] {
	ledger := qldb_ledgers[_]
	backup_enabled(ledger)
	p := fugue.allow_resource(ledger)
}

policy[p] {
	ledger := qldb_ledgers[_]
	not backup_enabled(ledger)
	p := fugue.deny_resource_with_message(ledger, "QLDB ledger does not have adequate backup and recovery settings.")
}
