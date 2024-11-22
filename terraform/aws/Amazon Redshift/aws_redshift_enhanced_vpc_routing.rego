package rules.redshift_enhanced_vpc_routing

import data.fugue

__rego__metadoc__ := {
	"id": "Redshift.7",
	"title": "Redshift clusters should use enhanced VPC routing",
	"description": "Redshift clusters must use enhanced VPC routing to force COPY and UNLOAD traffic through VPC for better security control.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_Redshift.7"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

aws_redshift_clusters := fugue.resources("aws_redshift_cluster")

# Check if enhanced VPC routing is enabled
is_vpc_routing_enabled(cluster) {
	cluster.enhanced_vpc_routing == true
}

# Allow clusters with enhanced VPC routing enabled
policy[p] {
	cluster := aws_redshift_clusters[_]
	is_vpc_routing_enabled(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny clusters without enhanced VPC routing
policy[p] {
	cluster := aws_redshift_clusters[_]
	not is_vpc_routing_enabled(cluster)
	p = fugue.deny_resource_with_message(cluster, "Redshift cluster must have enhanced VPC routing enabled for better security control")
}
