package rules.redshift_default_db_name

import data.fugue

__rego__metadoc__ := {
	"id": "Redshift.9",
	"title": "Redshift clusters should not use the default database name",
	"description": "Redshift clusters must use custom database names instead of default 'dev' name for enhanced security and compliance.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_Redshift.9"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

aws_redshift_clusters := fugue.resources("aws_redshift_cluster")

# Check if database name is not the default
is_custom_db_name(cluster) {
	cluster.database_name != "dev"
}

# Allow clusters with custom database name
policy[p] {
	cluster := aws_redshift_clusters[_]
	is_custom_db_name(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny clusters using default database name
policy[p] {
	cluster := aws_redshift_clusters[_]
	not is_custom_db_name(cluster)
	p = fugue.deny_resource_with_message(cluster, "Redshift cluster is using the default database name 'dev'. Use a custom database name instead.")
}
