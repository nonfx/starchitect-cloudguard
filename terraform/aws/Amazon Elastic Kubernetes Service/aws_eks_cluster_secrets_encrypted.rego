package rules.eks_cluster_secrets_encrypted

import data.fugue

__rego__metadoc__ := {
	"id": "EKS.3",
	"title": "EKS clusters should use encrypted Kubernetes secrets",
	"description": "EKS clusters must encrypt Kubernetes secrets using AWS KMS keys for enhanced security of sensitive data stored in etcd.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_EKS.3"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all EKS clusters
eks_clusters = fugue.resources("aws_eks_cluster")

# Helper to check if encryption configuration is properly set
has_encryption_config(cluster) {
	config := cluster.encryption_config[_]
	config.provider[_].key_arn != null
	config.resources[_] == "secrets"
}

# Allow clusters with encryption config
policy[p] {
	cluster := eks_clusters[_]
	has_encryption_config(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny clusters without encryption config
policy[p] {
	cluster := eks_clusters[_]
	not has_encryption_config(cluster)
	p = fugue.deny_resource_with_message(cluster, "EKS cluster must have encryption configuration enabled for Kubernetes secrets")
}
