package rules.aws_documentdb_disaster_recovery

import data.fugue

__rego__metadoc__ := {
	"id": "7.9",
	"title": "Ensure to Implement Backup and Disaster Recovery",
	"description": "Set up automated backups for your DocumentDB instances to ensure data durability and recoverability. Consider implementing a disaster recovery plan that includes data replication across different availability zones or regions.",
	"custom": {
		"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_7.9"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

documentdb_clusters := fugue.resources("aws_docdb_cluster")

backup_enabled(cluster) {
	cluster.backup_retention_period > 0
}

has_proper_availability_zones(cluster) {
	count(cluster.availability_zones) > 1
}

final_snapshot_configured(cluster) {
	not cluster.skip_final_snapshot
	cluster.final_snapshot_identifier != null
}

deletion_protection_enabled(cluster) {
	cluster.deletion_protection
}

policy[p] {
	cluster := documentdb_clusters[_]
	backup_enabled(cluster)
	has_proper_availability_zones(cluster)
	final_snapshot_configured(cluster)
	deletion_protection_enabled(cluster)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := documentdb_clusters[_]
	not backup_enabled(cluster)
	msg := sprintf("DocumentDB cluster '%s' does not have adequate backup setup.", [cluster.id])
	p = fugue.deny_resource_with_message(cluster, msg)
}

policy[p] {
	cluster := documentdb_clusters[_]
	not has_proper_availability_zones(cluster)
	msg := sprintf("DocumentDB cluster '%s' does not have adequate disaster recovery setup.", [cluster.id])
	p = fugue.deny_resource_with_message(cluster, msg)
}

policy[p] {
	cluster := documentdb_clusters[_]
	not final_snapshot_configured(cluster)
	msg := sprintf("DocumentDB cluster '%s' does not have final snapshot configured.", [cluster.id])
	p = fugue.deny_resource_with_message(cluster, msg)
}

policy[p] {
	cluster := documentdb_clusters[_]
	not deletion_protection_enabled(cluster)
	msg := sprintf("DocumentDB cluster '%s' does not have deletion protection enabled.", [cluster.id])
	p = fugue.deny_resource_with_message(cluster, msg)
}
