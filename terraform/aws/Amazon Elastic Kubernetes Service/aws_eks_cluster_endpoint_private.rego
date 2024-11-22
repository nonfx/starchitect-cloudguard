package rules.eks_cluster_endpoint_private

import data.fugue

__rego__metadoc__ := {
	"id": "EKS.1",
	"title": "EKS cluster endpoints should not be publicly accessible",
	"description": "EKS cluster endpoints must be private to prevent unauthorized access, requiring secure IAM and RBAC authentication methods.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_EKS.1"]}, "severity": "High"},
}

resource_type := "MULTIPLE"

# Get all EKS clusters
eks_clusters = fugue.resources("aws_eks_cluster")

# Helper to check if endpoint access is private
is_private_access(cluster) {
	vpc_config := cluster.vpc_config[_]
	vpc_config.endpoint_private_access == true
	vpc_config.endpoint_public_access == false
}

# Allow clusters with private endpoint access only
policy[p] {
	cluster := eks_clusters[_]
	is_private_access(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny clusters with public endpoint access
policy[p] {
	cluster := eks_clusters[_]
	not is_private_access(cluster)
	p = fugue.deny_resource_with_message(
		cluster,
		"EKS cluster endpoint should not be publicly accessible",
	)
}
