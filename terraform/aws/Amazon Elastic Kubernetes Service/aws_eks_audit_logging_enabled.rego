package rules.eks_audit_logging_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "EKS.8",
	"title": "EKS clusters should have audit logging enabled",
	"description": "EKS clusters must enable audit logging for security compliance, sending control plane logs to CloudWatch for monitoring and diagnostics.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_EKS.8"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all EKS clusters
eks_clusters = fugue.resources("aws_eks_cluster")

# Helper to check if audit logging is enabled
has_audit_logging(cluster) {
	enabled_types := cluster.enabled_cluster_log_types[_]
	enabled_types == "audit"
}

# Allow clusters with audit logging enabled
policy[p] {
	cluster := eks_clusters[_]
	has_audit_logging(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny clusters without audit logging
policy[p] {
	cluster := eks_clusters[_]
	not has_audit_logging(cluster)
	p = fugue.deny_resource_with_message(
		cluster,
		"EKS cluster must have audit logging enabled for security compliance and monitoring",
	)
}
