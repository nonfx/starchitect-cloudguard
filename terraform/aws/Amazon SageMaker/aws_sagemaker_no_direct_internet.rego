package rules.sagemaker_no_direct_internet

import data.fugue

__rego__metadoc__ := {
	"id": "SageMaker.1",
	"title": "Amazon SageMaker notebook instances should not have direct internet access",
	"description": "SageMaker notebook instances must disable direct internet access and use VPC endpoints for secure network connectivity.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_SageMaker.1"]}, "severity": "High", "author": "llmagent", "reviewer": "ssghait.007@gmail.com"},
}

resource_type = "MULTIPLE"

notebook_instances = fugue.resources("aws_sagemaker_notebook_instance")

has_direct_internet_access(resource) {
	resource.direct_internet_access == "Enabled"
}

policy[p] {
	resource := notebook_instances[_]
	has_direct_internet_access(resource)
	p = fugue.deny_resource_with_message(resource, "SageMaker notebook instance must have direct internet access disabled")
}

policy[p] {
	resource := notebook_instances[_]
	not has_direct_internet_access(resource)
	p = fugue.allow_resource(resource)
}
