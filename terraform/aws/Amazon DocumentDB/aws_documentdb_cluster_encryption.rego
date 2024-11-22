package rules.documentdb_cluster_encryption

import data.fugue

__rego__metadoc__ := {
	"id": "DocumentDB.1",
	"title": "Amazon DocumentDB clusters should be encrypted at rest",
	"description": "Amazon DocumentDB clusters must implement encryption at rest using AES-256 for enhanced data security and compliance.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_DocumentDB.1"]},"severity":"Medium","author":"Starchitect Agent"},
}

# Define resource type for multiple resources
resource_type := "MULTIPLE"

# Get all DocumentDB cluster resources
docdb_clusters = fugue.resources("aws_docdb_cluster")

# Helper function to check if cluster is encrypted
is_encrypted(cluster) {
	cluster.storage_encrypted == true
}

# Policy rule for allowing encrypted clusters
policy[p] {
	cluster := docdb_clusters[_]
	is_encrypted(cluster)
	p = fugue.allow_resource(cluster)
}

# Policy rule for denying unencrypted clusters
policy[p] {
	cluster := docdb_clusters[_]
	not is_encrypted(cluster)
	p = fugue.deny_resource_with_message(
		cluster,
		"DocumentDB cluster must be encrypted at rest using AWS KMS encryption",
	)
}
