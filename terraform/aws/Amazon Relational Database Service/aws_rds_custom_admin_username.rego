package rules.rds_custom_admin_username

import data.fugue
import future.keywords.in

__rego__metadoc__ := {
	"id": "RDS.24",
	"title": "RDS Database clusters should use a custom administrator username",
	"description": "RDS database clusters must use custom administrator usernames instead of default values to enhance security.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.24"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

rds_clusters = fugue.resources("aws_rds_cluster")

# List of default admin usernames to check against
default_admin_usernames = ["admin", "postgres", "root"]

# Check if username is a default value
is_default_username(cluster) {
	some username in default_admin_usernames
	cluster.master_username == username
}

# Check if engine is not Neptune or DocumentDB
is_applicable_engine(cluster) {
	not cluster.engine == "neptune"
	not cluster.engine == "docdb"
}

# Allow clusters with custom admin username
policy[p] {
	cluster := rds_clusters[_]
	is_applicable_engine(cluster)
	not is_default_username(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny clusters using default admin username
policy[p] {
	cluster := rds_clusters[_]
	is_applicable_engine(cluster)
	is_default_username(cluster)
	p = fugue.deny_resource_with_message(cluster, "RDS cluster must use a custom administrator username instead of default values")
}
