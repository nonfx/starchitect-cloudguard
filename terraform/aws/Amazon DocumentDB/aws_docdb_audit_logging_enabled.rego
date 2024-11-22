package rules.docdb_audit_logging_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "DocumentDB.4",
	"title": "Amazon DocumentDB clusters should publish audit logs to CloudWatch Logs",
	"description": "Amazon DocumentDB clusters must enable audit logging to CloudWatch Logs for security monitoring and compliance tracking.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_DocumentDB.4"]}, "severity": "Medium"},
}

resource_type := "MULTIPLE"

docdb_clusters = fugue.resources("aws_docdb_cluster")

# Helper function to check if audit logging is enabled
has_audit_logging(cluster) {
	cluster.enabled_cloudwatch_logs_exports[_] == "audit"
}

# Policy rule for allowing clusters with audit logging
policy[p] {
	cluster := docdb_clusters[_]
	has_audit_logging(cluster)
	p = fugue.allow_resource(cluster)
}

# Policy rule for denying clusters without audit logging
policy[p] {
	cluster := docdb_clusters[_]
	not has_audit_logging(cluster)
	p = fugue.deny_resource_with_message(
		cluster,
		"DocumentDB cluster must have audit logging enabled and published to CloudWatch Logs",
	)
}
