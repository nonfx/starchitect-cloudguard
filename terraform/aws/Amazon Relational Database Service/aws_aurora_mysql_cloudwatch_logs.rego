package rules.aurora_mysql_cloudwatch_logs

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.34",
	"title": "Aurora MySQL DB clusters should publish audit logs to CloudWatch Logs",
	"description": "Ensures that Aurora MySQL DB clusters are configured to publish audit logs to CloudWatch Logs for monitoring and compliance purposes.",
	"custom": {"severity": "Medium", "controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.34"]}, "author": "Starchitect Agent"},
}

# Define the resource type we're evaluating
resource_type := "MULTIPLE"

aws_rds_cluster := fugue.resources("aws_rds_cluster")

# Helper function to check if cluster is Aurora MySQL
is_aurora_mysql(cluster) {
	startswith(cluster.engine, "aurora-mysql")
}

# Helper function to check if audit logs are enabled
has_audit_logs(cluster) {
	logs := cluster.enabled_cloudwatch_logs_exports[_]
	logs == "audit"
}

# Allow rule for compliant clusters
policy[p] {
	cluster := aws_rds_cluster[_]
	is_aurora_mysql(cluster)
	has_audit_logs(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny rule for non-compliant clusters
policy[p] {
	cluster := aws_rds_cluster[_]
	is_aurora_mysql(cluster)
	not has_audit_logs(cluster)
	p = fugue.deny_resource_with_message(
		cluster,
		"Aurora MySQL clusters must have audit logs enabled in CloudWatch Logs exports",
	)
}
