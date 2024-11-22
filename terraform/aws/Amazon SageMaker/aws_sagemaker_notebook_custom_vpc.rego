package rules.sagemaker_notebook_custom_vpc

import data.fugue

__rego__metadoc__ := {
	"id": "SageMaker.2",
	"title": "SageMaker notebook instances should be launched in a custom VPC",
	"description": "This control checks whether SageMaker notebook instances are launched within a custom VPC. Launching instances in a custom VPC provides enhanced network security and control.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_SageMaker.2"]}, "severity": "High", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

sagemaker_instances = fugue.resources("aws_sagemaker_notebook_instance")

# Helper function to check if instance is in VPC
is_in_vpc(instance) {
	instance.subnet_id != null
	instance.subnet_id != ""
}

policy[p] {
	instance := sagemaker_instances[_]
	is_in_vpc(instance)
	p = fugue.allow_resource(instance)
}

policy[p] {
	instance := sagemaker_instances[_]
	not is_in_vpc(instance)
	p = fugue.deny_resource_with_message(instance, "SageMaker notebook instance must be launched in a custom VPC")
}
