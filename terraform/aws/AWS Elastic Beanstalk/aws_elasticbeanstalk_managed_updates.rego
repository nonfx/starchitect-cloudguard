package rules.aws_elasticbeanstalk_managed_updates

import data.fugue

__rego__metadoc__ := {
	"id": "6.1",
	"title": "Ensure Managed Platform updates is configured",
	"description": "AWS Elastic Beanstalk regularly releases platform updates to provide fixes, software updates, and new features. With managed platform updates, you can configure your environment to automatically upgrade to the latest version of a platform during a scheduled maintenance window. Your application remains in service during the update process with no reduction in capacity. Managed updates are available on both single-instance and load-balanced environments. They also ensure you aren't introducing any vulnerabilities by running legacy systems that require updates and patches.",
	"custom": {"controls":{"CIS-AWS-Compute-Services-Benchmark_v1.0.0":["CIS-AWS-Compute-Services-Benchmark_v1.0.0_6.1"]},"author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

elastic_beanstalk_environments := fugue.resources("aws_elastic_beanstalk_environment")

managed_updates_enabled(resource) {
	some i
	resource.setting[i].name == "ManagedActionsEnabled"
	lower(resource.setting[i].value) == "true"
}

policy[p] {
	resource := elastic_beanstalk_environments[_]
	managed_updates_enabled(resource)
	p := fugue.allow_resource(resource)
}

policy[p] {
	resource := elastic_beanstalk_environments[_]
	not managed_updates_enabled(resource)
	p := fugue.deny_resource_with_message(resource, "Managed Platform updates is not configured for this Elastic Beanstalk environment")
}
