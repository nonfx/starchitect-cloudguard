package rules.rds_cluster_iam_auth_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.12",
	"title": "IAM authentication should be configured for RDS clusters",
	"description": "IAM authentication should be enabled for RDS clusters to allow password-free, token-based authentication with SSL encryption.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.12"]}, "severity": "Medium", "author": "llmagent"},
}

resource_type := "MULTIPLE"

rds_clusters = fugue.resources("aws_rds_cluster")

# Helper function to check if IAM authentication is enabled
is_iam_auth_enabled(cluster) {
	cluster.iam_database_authentication_enabled == true
}

# Allow clusters with IAM authentication enabled
policy[p] {
	cluster := rds_clusters[_]
	is_iam_auth_enabled(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny clusters without IAM authentication
policy[p] {
	cluster := rds_clusters[_]
	not is_iam_auth_enabled(cluster)
	p = fugue.deny_resource_with_message(cluster, "RDS cluster must have IAM authentication enabled for secure access management")
}
