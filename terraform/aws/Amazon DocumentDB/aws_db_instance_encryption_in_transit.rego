package rules.aws_db_instance_encryption_in_transit

import data.fugue

resource_type := "MULTIPLE"

__rego__metadoc__ := {
	"id": "7.4",
	"title": "Ensure Encryption in Transit is Enabled for RDS",
	"description": "Amazon RDS uses SSL/TLS to encrypt data during transit. To secure your data in transit, the individual should identify their client application and what is supported by TLS to configure it correctly.",
	"custom": {
		"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_7.4"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

docdb_clusters = fugue.resources("aws_docdb_cluster")

is_encryption_in_transit_enabled(cluster) {
	cluster.storage_encrypted == true
}

policy[p] {
	cluster := docdb_clusters[_]
	is_encryption_in_transit_enabled(cluster)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := docdb_clusters[_]
	not is_encryption_in_transit_enabled(cluster)
	p = fugue.deny_resource_with_message(cluster, "Encryption in transit is not enabled for this Amazon DocumentDB cluster")
}
