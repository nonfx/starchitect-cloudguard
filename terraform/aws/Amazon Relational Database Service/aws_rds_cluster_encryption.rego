package rules.rds_cluster_encryption

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.27",
	"title": "RDS DB clusters should be encrypted at rest",
	"description": "RDS DB clusters must be encrypted at rest to protect data confidentiality and meet compliance requirements for data storage security.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.27"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Query for all RDS instances
aws_rds_cluster = fugue.resources("aws_rds_cluster")

# Check if cluster is encrypted
is_encrypted(cluster) {
	cluster.storage_encrypted == true
}

# Allow clusters that are encrypted
policy[p] {
	cluster := aws_rds_cluster[_]
	is_encrypted(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny clusters that are not encrypted
policy[p] {
	cluster := aws_rds_cluster[_]
	not is_encrypted(cluster)
	p = fugue.deny_resource_with_message(
		cluster,
		"RDS DB cluster must be encrypted at rest using storage_encrypted = true",
	)
}
