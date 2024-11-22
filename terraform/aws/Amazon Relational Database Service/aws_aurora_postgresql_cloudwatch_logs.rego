package rules.aurora_postgresql_cloudwatch_logs

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.37",
	"title": "Aurora PostgreSQL DB clusters should publish logs to CloudWatch Logs",
	"description": "This control checks whether Aurora PostgreSQL DB clusters are configured to publish logs to Amazon CloudWatch Logs.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.37"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

aws_rds_cluster := fugue.resources("aws_rds_cluster")

# Check if cluster is Aurora PostgreSQL
is_aurora_postgresql(cluster) {
	startswith(cluster.engine, "aurora-postgresql")
}

# Check if logging is enabled for PostgreSQL logs
has_postgresql_logs(cluster) {
	log_types := cluster.enabled_cloudwatch_logs_exports
	log_types[_] == "postgresql"
}

# Allow Aurora PostgreSQL clusters with PostgreSQL logs enabled
policy[p] {
	cluster := aws_rds_cluster[_]
	is_aurora_postgresql(cluster)
	has_postgresql_logs(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny Aurora PostgreSQL clusters without PostgreSQL logs
policy[p] {
	cluster := aws_rds_cluster[_]
	is_aurora_postgresql(cluster)
	not has_postgresql_logs(cluster)
	p = fugue.deny_resource_with_message(
		cluster,
		"Aurora PostgreSQL cluster must be configured to publish PostgreSQL logs to CloudWatch Logs",
	)
}
