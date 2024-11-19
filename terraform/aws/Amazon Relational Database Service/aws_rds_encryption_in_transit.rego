package rules.aws_rds_encryption_in_transit

import data.fugue

__rego__metadoc__ := {
	"author": "sachin@nonfx.com",
	"id": "3.6",
	"title": "Enable Encryption in Transit",
	"description": "Amazon Relational Database uses SSL/TLS to encrypt data during transit. To secure your data in transit the individual should identify their client application and what is supported by SSL/TLS to configure it correctly",
	"custom": {
		"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_3.6"]},
		"severity": "Low",
	},
}

resource_type := "MULTIPLE"

rds_clusters := fugue.resources("aws_rds_cluster")

ssl_enforcement_enabled(rds_cluster) {
	rds_cluster.iam_database_authentication_enabled == true
}

policy[p] {
	rds_cluster := rds_clusters[_]
	ssl_enforcement_enabled(rds_cluster)
	p = fugue.allow_resource(rds_cluster)
}

policy[p] {
	rds_cluster := rds_clusters[_]
	not ssl_enforcement_enabled(rds_cluster)
	msg := sprintf("RDS cluster '%s' does not have encryption in transit enabled. Enable SSL/TLS for data in transit.", [rds_cluster])
	p = fugue.deny_resource_with_message(rds_cluster, msg)
}
