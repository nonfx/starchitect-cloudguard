package rules.sagemaker_endpoint_instance_count

import data.fugue

__rego__metadoc__ := {
	"id": "SageMaker.4",
	"title": "SageMaker endpoint production variants should have an initial instance count greater than 1",
	"description": "This control checks if SageMaker endpoint production variants have multiple instances for high availability and redundancy across Availability Zones.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_SageMaker.4"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

sagemaker_endpoint_configs = fugue.resources("aws_sagemaker_endpoint_configuration")

# Helper function to check if production variant has sufficient instances
has_sufficient_instances(variant) {
	variant.initial_instance_count > 1
}

# Policy rule for checking endpoint configurations
policy[p] {
	config := sagemaker_endpoint_configs[_]
	variant := config.production_variants[_]
	has_sufficient_instances(variant)
	p = fugue.allow_resource(config)
}

policy[p] {
	config := sagemaker_endpoint_configs[_]
	variant := config.production_variants[_]
	not has_sufficient_instances(variant)
	p = fugue.deny_resource_with_message(config, "SageMaker endpoint production variant must have more than one instance for high availability")
}
