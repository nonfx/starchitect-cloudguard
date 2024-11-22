package rules.elastic_beanstalk_enhanced_health_reporting

import data.fugue

__rego__metadoc__ := {
	"id": "ElasticBeanstalk.1",
	"title": "Elastic Beanstalk environments should have enhanced health reporting enabled",
	"description": "Elastic Beanstalk environments must enable enhanced health reporting for better infrastructure monitoring and rapid response to health changes.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_ElasticBeanstalk.1"]}, "severity": "Low"},
}

resource_type := "MULTIPLE"

# Get all Elastic Beanstalk environments
environments = fugue.resources("aws_elastic_beanstalk_environment")

# Helper to check if enhanced health reporting is enabled
has_enhanced_health(env) {
	setting := env.setting[_]
	setting.namespace == "aws:elasticbeanstalk:healthreporting:system"
	setting.name == "SystemType"
	setting.value == "enhanced"
}

# Allow environments with enhanced health reporting
policy[p] {
	env := environments[_]
	has_enhanced_health(env)
	p = fugue.allow_resource(env)
}

# Deny environments without enhanced health reporting
policy[p] {
	env := environments[_]
	not has_enhanced_health(env)
	p = fugue.deny_resource_with_message(
		env,
		"Elastic Beanstalk environment should have enhanced health reporting enabled",
	)
}
