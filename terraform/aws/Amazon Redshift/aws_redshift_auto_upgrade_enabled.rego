package rules.redshift_auto_upgrade_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "Redshift.6",
	"title": "Amazon Redshift should have automatic upgrades to major versions enabled",
	"description": "Amazon Redshift clusters must enable automatic major version upgrades for security patches and bug fixes during maintenance windows.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Redshift.6"]}, "severity": "Medium", "author": "llmagent"},
}

# Define resource type for Redshift clusters
resource_type := "MULTIPLE"

# Get all Redshift clusters
clusters = fugue.resources("aws_redshift_cluster")

# Allow if cluster has automatic upgrades enabled
policy[p] {
	cluster := clusters[_]
	cluster.allow_version_upgrade == true
	p := fugue.allow_resource(cluster)
}

# Deny if cluster has automatic upgrades disabled
policy[p] {
	cluster := clusters[_]
	cluster.allow_version_upgrade == false
	p := fugue.deny_resource_with_message(
		cluster,
		sprintf("Redshift cluster '%s' must have automatic version upgrades enabled", [cluster.cluster_identifier]),
	)
}
