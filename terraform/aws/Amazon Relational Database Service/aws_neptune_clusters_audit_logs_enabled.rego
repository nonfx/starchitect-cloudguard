package rules.neptune_clusters_audit_logs_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "Neptune.2",
	"title": "Neptune DB clusters should publish audit logs to CloudWatch Logs",
	"description": "This control checks if Neptune DB clusters publish audit logs to CloudWatch Logs for monitoring and compliance tracking of database operations.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_Neptune.2"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

neptune_clusters = fugue.resources("aws_neptune_cluster")

# Helper function to check if audit logging is enabled
has_audit_logs_enabled(cluster) {
	cluster.enable_cloudwatch_logs_exports[_] == "audit"
}

policy[p] {
	cluster := neptune_clusters[_]
	has_audit_logs_enabled(cluster)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := neptune_clusters[_]
	not has_audit_logs_enabled(cluster)
	p = fugue.deny_resource_with_message(cluster, "Neptune DB cluster must publish audit logs to CloudWatch Logs")
}
