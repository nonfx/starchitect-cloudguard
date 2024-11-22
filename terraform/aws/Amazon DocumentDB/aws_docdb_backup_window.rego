package rules.aws_docdb_backup_window

import data.fugue

__rego__metadoc__ := {
	"id": "7.10",
	"title": "Ensure to Configure Backup Window",
	"description": "",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_7.10"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

docdb_clusters = fugue.resources("aws_docdb_cluster")

# Function to check if a CloudWatch alarm is associated with a DocumentDB cluster
has_backup_window(cluster) {
	cluster.preferred_backup_window
	cluster.preferred_backup_window != ""
}

# Policy for DocumentDB clusters
policy[p] {
	cluster := docdb_clusters[_]
	has_backup_window(cluster)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := docdb_clusters[_]
	not has_backup_window(cluster)
	msg := sprintf("%s does not have backup window set", [cluster.cluster_identifier])
	p = fugue.deny_resource_with_message(cluster, msg)
}
