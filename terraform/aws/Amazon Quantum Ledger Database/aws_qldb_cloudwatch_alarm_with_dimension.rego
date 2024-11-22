package rules.aws_qldb_cloudwatch_alarm_with_dimension

import data.fugue

__rego__metadoc__ := {
	"id": "11.6.a",
	"title": "Ensure Monitoring and Logging is Enabled - Monitoring",
	"description": "Enable QLDB's built-in logging to capture important system events and database activity. Monitor the logs for any suspicious activities or errors. Leverage Amazon CloudWatch to collect and analyze logs, set up alarms, and receive notifications for potential security incidents.",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_11.6"]},"author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

cloudwatch_alarms = fugue.resources("aws_cloudwatch_metric_alarm")

qldb_ledgers = fugue.resources("aws_qldb_ledger")

# Check if any CloudWatch alarm is associated with QLDB and has the LedgerName dimension
alarm_for_qldb_with_ledgername(alarm, qldb_ledger) {
	alarm.namespace == "AWS/QLDB"
	alarm.dimensions.LedgerName == qldb_ledger.name
}

policy[p] {
	qldb_ledger = qldb_ledgers[_]
	alarm := cloudwatch_alarms[_]
	not alarm_for_qldb_with_ledgername(alarm, qldb_ledger)
	msg = sprintf("CloudWatch alarm %s is not associated with QLDB", [qldb_ledger.name])
	p = fugue.deny_resource_with_message(qldb_ledger, msg)
}

policy[p] {
	qldb_ledger = qldb_ledgers[_]
	alarm := cloudwatch_alarms[_]
	alarm_for_qldb_with_ledgername(alarm, qldb_ledger)
	p = fugue.allow_resource(qldb_ledger)
}
