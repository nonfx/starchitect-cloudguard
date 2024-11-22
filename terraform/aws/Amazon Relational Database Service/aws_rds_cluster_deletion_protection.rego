package rules.rds_cluster_deletion_protection

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.7",
	"title": "RDS clusters should have deletion protection enabled",
	"description": "This control checks if RDS DB clusters have deletion protection enabled to prevent accidental or unauthorized database deletion.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.7"]},"severity":"Low","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

aws_rds_clusters = fugue.resources("aws_rds_cluster")

# Helper function to check if deletion protection is enabled
is_deletion_protected(cluster) {
	cluster.deletion_protection == true
}

# Allow clusters with deletion protection enabled
policy[p] {
	cluster := aws_rds_clusters[_]
	is_deletion_protected(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny clusters without deletion protection
policy[p] {
	cluster := aws_rds_clusters[_]
	not is_deletion_protected(cluster)
	p = fugue.deny_resource_with_message(cluster, "RDS cluster must have deletion protection enabled to prevent accidental deletion")
}
