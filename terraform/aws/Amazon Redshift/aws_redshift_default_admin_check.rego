package rules.redshift_default_admin_check

import data.fugue

__rego__metadoc__ := {
	"id": "Redshift.8",
	"title": "Amazon Redshift clusters should not use the default Admin username",
	"description": "Amazon Redshift clusters must use a custom admin username instead of the default 'awsuser' for enhanced security.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Redshift.8"]}, "severity": "Medium", "author": "llmagent"},
}

resource_type := "MULTIPLE"

aws_redshift_clusters := fugue.resources("aws_redshift_cluster")

# Check if admin username is not the default
is_custom_admin_username(cluster) {
	cluster.master_username != "awsuser"
}

# Allow clusters with custom admin username
policy[p] {
	cluster := aws_redshift_clusters[_]
	is_custom_admin_username(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny clusters using default admin username
policy[p] {
	cluster := aws_redshift_clusters[_]
	not is_custom_admin_username(cluster)
	p = fugue.deny_resource_with_message(cluster, "Redshift cluster is using the default admin username 'awsuser'. Use a custom username instead.")
}
