package rules.aws_aurora_encryption_at_rest

import data.fugue

__rego__metadoc__ := {
	"id": "2.3",
	"title": "Ensure Data at Rest is Encrypted",
	"description": "Amazon Aurora allows you to encrypt your databases using keys you manage through AWS Key Management Service (KMS).",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_2.3"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

aurora_clusters = fugue.resources("aws_rds_cluster")

aurora_encrypted(cluster) {
	cluster.storage_encrypted == true
}

aurora_has_kms_key(cluster) {
	cluster.kms_key_id != null
	cluster.kms_key_id != ""
}

policy[p] {
	cluster := aurora_clusters[_]
	aurora_encrypted(cluster)
	aurora_has_kms_key(cluster)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := aurora_clusters[_]
	not aurora_encrypted(cluster)
	p = fugue.deny_resource_with_message(cluster, "Aurora cluster does not have encryption at rest enabled")
}

policy[p] {
	cluster := aurora_clusters[_]
	aurora_encrypted(cluster)
	not aurora_has_kms_key(cluster)
	p = fugue.deny_resource_with_message(cluster, "Aurora cluster is encrypted but does not have a KMS key specified")
}
