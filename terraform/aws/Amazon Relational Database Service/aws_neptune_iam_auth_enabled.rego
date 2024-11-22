package rules.neptune_iam_auth_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "Neptune.7",
	"title": "Neptune DB clusters should have IAM database authentication enabled",
	"description": "This control checks whether Neptune DB clusters have IAM database authentication enabled. IAM database authentication provides secure, passwordless access management using AWS Signature Version 4 signing process.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Neptune.7"]}, "severity": "Medium"},
}

resource_type := "MULTIPLE"

neptune_clusters = fugue.resources("aws_neptune_cluster")

# Helper function to check if IAM authentication is enabled
is_iam_auth_enabled(cluster) {
	cluster.iam_database_authentication_enabled == true
}

policy[p] {
	cluster := neptune_clusters[_]
	is_iam_auth_enabled(cluster)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := neptune_clusters[_]
	not is_iam_auth_enabled(cluster)
	p = fugue.deny_resource_with_message(cluster, "Neptune DB cluster does not have IAM database authentication enabled")
}
