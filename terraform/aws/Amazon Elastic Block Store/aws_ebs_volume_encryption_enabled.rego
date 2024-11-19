# Rule must be in the rules package
package rules.ebs_volume_encryption_enabled

__rego__metadoc__ := {
	"author": "sachin@nonfx.com",
	"id": "2.2.1",
	"title": "Ensure EBS Volume Encryption is Enabled in all Regions",
	"description": "Elastic Compute Cloud (EC2) supports encryption at rest when using the Elastic Block Store (EBS) service. While disabled by default, forcing encryption at EBS volume creation is supported.",
	"custom": {"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_2.2.1"], "CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.2.1"]}, "severity": "Low", "reviewer": "ssghait.007@gmail.com"},
}

import data.fugue

# Mark this as an advanced rule
resource_type := "MULTIPLE"

# Query for all aws_ebs_volume and aws_ebs_encryption_by_default resources
ebs_volumes = fugue.resources("aws_ebs_volume")

ebs_encryption_settings = fugue.resources("aws_ebs_encryption_by_default")

# Auxiliary function to check if encryption is enabled
is_encryption_enabled(resource) {
	resource.enabled == true
}

# Policy rule that creates a set of judgements
policy[p] {
	count(ebs_volumes) > 0
	resource = ebs_encryption_settings[_]
	is_encryption_enabled(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	count(ebs_volumes) > 0
	resource = ebs_encryption_settings[_]
	not is_encryption_enabled(resource)
	p = fugue.deny_resource_with_message(resource, "EBS encryption is not enabled by default in this region")
}

# Check if the setting is missing only if EBS volumes exist
policy[p] {
	count(ebs_volumes) > 0
	count(ebs_encryption_settings) == 0
	p = fugue.missing_resource_with_message("aws_ebs_encryption_by_default", "EBS encryption setting is missing while EBS volumes are present")
}
