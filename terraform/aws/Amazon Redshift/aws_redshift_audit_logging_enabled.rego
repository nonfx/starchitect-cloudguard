package rules.redshift_audit_logging

import data.fugue

__rego__metadoc__ := {
	"id": "Redshift.4",
	"title": "Amazon Redshift clusters should have audit logging enabled",
	"description": "Amazon Redshift clusters must enable audit logging for security monitoring and compliance tracking. Audit logging provides information about connections and user activities in your database for security analysis and troubleshooting.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Redshift.4"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

# Get all Redshift clusters and logging configurations
clusters = fugue.resources("aws_redshift_cluster")

logging_configs = fugue.resources("aws_redshift_logging")

# Helper to check if logging is enabled for a cluster
has_logging(cluster) {
	config := logging_configs[_]
	config.cluster_identifier == cluster.cluster_identifier
}

# Allow if cluster has logging enabled
policy[p] {
	cluster := clusters[_]
	has_logging(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny if cluster exists but logging is not enabled
policy[p] {
	cluster := clusters[_]
	not has_logging(cluster)
	p = fugue.deny_resource_with_message(
		cluster,
		sprintf("Redshift cluster '%s' must have audit logging enabled", [cluster.cluster_identifier]),
	)
}
