package rules.redshift_automated_snapshots

import data.fugue

__rego__metadoc__ := {
	"id": "Redshift.3",
	"title": "Amazon Redshift clusters should have automatic snapshots enabled",
	"description": "Amazon Redshift clusters should have automated snapshots enabled with a minimum retention period of 7 days to support data recovery and system resilience.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Redshift.3"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

redshift_clusters = fugue.resources("aws_redshift_cluster")

# Check if automated snapshots are properly configured
is_snapshot_properly_configured(cluster) {
	cluster.automated_snapshot_retention_period >= 7
}

# Allow clusters with proper snapshot configuration
policy[p] {
	cluster := redshift_clusters[_]
	is_snapshot_properly_configured(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny clusters without proper snapshot configuration
policy[p] {
	cluster := redshift_clusters[_]
	not is_snapshot_properly_configured(cluster)
	p = fugue.deny_resource_with_message(cluster, "Redshift cluster must have automated snapshots enabled with a minimum retention period of 7 days")
}
