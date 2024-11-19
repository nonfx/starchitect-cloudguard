package rules.aws_rds_aurora_automatic_backups

import data.fugue

__rego__metadoc__ := {
	"author": "rajat@nonfx.com",
	"id": "2.10",
	"title": "Ensure Automatic Backups and Retention Policies are configured",
	"description": "Backups help protect your data from accidental loss or database failure. With Amazon Aurora, you can turn on automatic backups and specify a retention period. The backups include a daily snapshot of the entire DB instance and transaction logs",
	"custom": {
		"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_2.10"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

rds_clusters := fugue.resources("aws_rds_cluster")

valid_backup_retention_period(cluster) {
	cluster.backup_retention_period >= 1
	cluster.backup_retention_period <= 35
}

policy[p] {
	cluster := rds_clusters[_]
	valid_backup_retention_period(cluster)
	p := fugue.allow_resource(cluster)
}

policy[p] {
	cluster := rds_clusters[_]
	not valid_backup_retention_period(cluster)
	msg := sprintf("RDS Aurora cluster '%s' does not have a valid backup retention period. It should be between 1 and 35 days.", [cluster.id])
	p := fugue.deny_resource_with_message(cluster, msg)
}
