package rules.dax_clusters_encrypted_at_rest

import data.fugue

__rego__metadoc__ := {
	"id": "DynamoDB.3",
	"title": "DynamoDB Accelerator (DAX) clusters should be encrypted at rest",
	"description": "DynamoDB Accelerator (DAX) clusters must implement encryption at rest to protect data through additional access controls and API permissions.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_DynamoDB.3"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

dax_clusters = fugue.resources("aws_dax_cluster")

# Helper function to check if encryption is enabled
is_encrypted(cluster) {
	cluster.server_side_encryption[_].enabled == true
}

# Policy rule for encrypted clusters
policy[p] {
	cluster := dax_clusters[_]
	is_encrypted(cluster)
	p = fugue.allow_resource(cluster)
}

# Policy rule for unencrypted clusters
policy[p] {
	cluster := dax_clusters[_]
	not is_encrypted(cluster)
	p = fugue.deny_resource_with_message(cluster, "DAX cluster is not encrypted at rest")
}
