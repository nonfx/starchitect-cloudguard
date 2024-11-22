package rules.docdb_deletion_protection_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "DocumentDB.5",
	"title": "Amazon DocumentDB clusters should have deletion protection enabled",
	"description": "Amazon DocumentDB clusters must enable deletion protection to prevent accidental or unauthorized database deletion.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_DocumentDB.5"]}, "severity": "Medium"},
}

resource_type := "MULTIPLE"

docdb_clusters = fugue.resources("aws_docdb_cluster")

# Helper function to check if deletion protection is enabled
is_deletion_protected(cluster) {
	cluster.deletion_protection == true
}

# Policy rule for allowing protected clusters
policy[p] {
	cluster := docdb_clusters[_]
	is_deletion_protected(cluster)
	p = fugue.allow_resource(cluster)
}

# Policy rule for denying unprotected clusters
policy[p] {
	cluster := docdb_clusters[_]
	not is_deletion_protected(cluster)
	p = fugue.deny_resource_with_message(
		cluster,
		"DocumentDB cluster must have deletion protection enabled",
	)
}
