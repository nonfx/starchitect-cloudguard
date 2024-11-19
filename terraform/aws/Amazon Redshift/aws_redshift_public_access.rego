package rules.redshift_public_access

import data.fugue

__rego__metadoc__ := {
	"id": "Redshift.1",
	"title": "Amazon Redshift clusters should prohibit public access",
	"description": "Amazon Redshift clusters must be configured to prohibit public access for enhanced security and compliance with standards.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Redshift.1"]},
		"severity": "Critical",
	},
}

resource_type := "MULTIPLE"

# Get all Redshift clusters
clusters = fugue.resources("aws_redshift_cluster")

# Deny if cluster is publicly accessible
policy[p] {
	cluster := clusters[_]
	cluster.publicly_accessible == true
	p := fugue.deny_resource_with_message(
		cluster,
		sprintf(
			"Redshift cluster '%s' is publicly accessible and must be configured to prohibit public access",
			[cluster.cluster_identifier],
		),
	)
}

# Allow if cluster is not publicly accessible
policy[p] {
	cluster := clusters[_]
	cluster.publicly_accessible == false
	p := fugue.allow_resource(cluster)
}
