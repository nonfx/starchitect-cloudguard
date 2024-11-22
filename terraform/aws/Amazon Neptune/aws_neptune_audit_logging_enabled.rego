package rules.aws_neptune_audit_logging_enabled

import data.fugue
import future.keywords.in

__rego__metadoc__ := {
	"id": "9.5",
	"title": "Ensure Audit Logging is Enabled",
	"description": "This control is important because it helps ensure activity within the cluster and identifies who has last modified the document and who has access to it, in case of breaches. It also ensures compliance with regulation requirements.",
	"custom": {
		"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_9.5"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

aws_neptune_cluster = fugue.resources("aws_neptune_cluster")

audit_logging_enabled(resource) {
	"audit" in resource.enable_cloudwatch_logs_exports
}

policy[p] {
	resource := aws_neptune_cluster[_]
	audit_logging_enabled(resource)
	p := fugue.allow_resource(resource)
}

policy[p] {
	resource := aws_neptune_cluster[_]
	not audit_logging_enabled(resource)
	p := fugue.deny_resource_with_message(resource, "Audit logging should be enabled for Amazon Neptune clusters.")
}
