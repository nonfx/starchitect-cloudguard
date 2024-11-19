package rules.aws_qldb_encryption_at_rest

import data.fugue

__rego__metadoc__ := {
	"author": "ankit@nonfx.com",
	"id": "11.3",
	"title": "Ensure Data at Rest is Encrypted",
	"description": "This helps ensure that the data is kept secure and protected when at rest. The user must choose from two key options which then determine when the data is encrypted at rest.",
	"custom": {"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_11.3"]}},
}

resource_type := "MULTIPLE"

qldb_ledgers := fugue.resources("aws_qldb_ledger")

ledger_encrypted(ledger) {
	ledger.kms_key != null
	ledger.kms_key != ""
}

policy[p] {
	ledger := qldb_ledgers[_]
	ledger_encrypted(ledger)
	p := fugue.allow_resource(ledger)
}

policy[p] {
	ledger := qldb_ledgers[_]
	not ledger_encrypted(ledger)
	p := fugue.deny_resource_with_message(ledger, "QLDB ledger is not encrypted at rest using a KMS key")
}
