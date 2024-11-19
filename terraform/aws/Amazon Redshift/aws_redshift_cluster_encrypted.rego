package rules.redshift_cluster_encrypted

import data.fugue

__rego__metadoc__ := {
	"id": "Redshift.10",
	"title": "Redshift clusters should be encrypted at rest",
	"description": "Redshift clusters must be encrypted at rest using KMS encryption to protect data stored on disk.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Redshift.10"]}, "severity": "Medium", "author": "llmagent"},
}

resource_type := "MULTIPLE"

redshift_clusters = fugue.resources("aws_redshift_cluster")

# Check if cluster is encrypted
is_encrypted(cluster) {
	cluster.encrypted == true
}

# Allow clusters that are encrypted
policy[p] {
	cluster := redshift_clusters[_]
	is_encrypted(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny clusters that are not encrypted
policy[p] {
	cluster := redshift_clusters[_]
	not is_encrypted(cluster)
	p = fugue.deny_resource_with_message(cluster, "Redshift cluster must be encrypted at rest")
}
