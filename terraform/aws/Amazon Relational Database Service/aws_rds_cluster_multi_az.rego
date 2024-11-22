package rules.rds_cluster_multi_az

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.15",
	"title": "RDS DB clusters should be configured for multiple Availability Zones",
	"description": "This control checks whether RDS DB clusters are configured with multiple Availability Zones for high availability and automated failover capabilities.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.15"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

rds_clusters = fugue.resources("aws_rds_cluster")

# Helper function to check if multi-AZ is enabled
is_multi_az_enabled(cluster) {
	cluster.availability_zones != null
	count(cluster.availability_zones) > 1
}

# Allow clusters with multi-AZ enabled
policy[p] {
	cluster := rds_clusters[_]
	is_multi_az_enabled(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny clusters without multi-AZ
policy[p] {
	cluster := rds_clusters[_]
	not is_multi_az_enabled(cluster)
	p = fugue.deny_resource_with_message(cluster, "RDS DB cluster must be configured with multiple Availability Zones for high availability")
}
