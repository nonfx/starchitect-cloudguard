package rules.aws_qldb_logging_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "11.6.b",
	"title": "Ensure Monitoring and Logging is Enabled - Logging",
	"description": "Enable QLDB's built-in logging to capture important system events and database activity. Monitor the logs for any suspicious activities or errors. Leverage Amazon CloudWatch to collect and analyze logs, set up alarms, and receive notifications for potential security incidents.",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_11.6"]},"author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

qldb_ledgers := fugue.resources("aws_qldb_ledger")

cloudtrails := fugue.resources("aws_cloudtrail")

cloudwatch_log_groups := fugue.resources("aws_cloudwatch_log_group")

has_cloudtrail_enabled(ledger) {
	trail := cloudtrails[_]
	trail.enable_logging == true
	ledger.name == trail.name
}

has_cloudwatch_logging_enabled(ledger) {
	log_group := cloudwatch_log_groups[_]
	contains(log_group.name, ledger.name)
}

policy[p] {
	ledger := qldb_ledgers[_]
	has_cloudtrail_enabled(ledger)
	has_cloudwatch_logging_enabled(ledger)
	p := fugue.allow_resource(ledger)
}

policy[p] {
	ledger := qldb_ledgers[_]
	not has_cloudtrail_enabled(ledger)
	msg := sprintf("QLDB ledger '%s' does not have CloudTrail logging enabled", [ledger.name])
	p := fugue.deny_resource_with_message(ledger, msg)
}

policy[p] {
	ledger := qldb_ledgers[_]
	not has_cloudwatch_logging_enabled(ledger)
	msg := sprintf("QLDB ledger '%s' does not have CloudWatch logging enabled", [ledger.name])
	p := fugue.deny_resource_with_message(ledger, msg)
}
