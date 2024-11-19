package rules.aws_config_enabled_all_regions

import data.fugue

__rego__metadoc__ := {
	"author": "sachin@nonfx.com",
	"id": "3.3",
	"title": "Ensure AWS Config is enabled in all regions",
	"description": "AWS Config is a web service that performs configuration management of supported AWS resources within your account and delivers log files to you. The recorded information includes the configuration item (AWS resource), relationships between configuration items (AWS resources), any configuration changes between resources. It is recommended AWS Config be enabled in all regions.",
	"custom": {
		"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_3.3"]},
		"severity": "High",
	},
}

resource_type := "MULTIPLE"

config_aggregators := fugue.resources("aws_config_configuration_aggregator")

config_all_regions_enabled(aggregator) {
	aggregator.account_aggregation_source[_].all_regions == true
	aggregator.organization_aggregation_source[_].all_regions == true
}

policy[p] {
	aggregator := config_aggregators[_]
	aggregator_name := aggregator.id
	not config_all_regions_enabled(aggregator)
	msg := sprintf("Config Aggregator '%s' is not properly configured. Ensure it is enabled in all regions.", [aggregator_name])
	p = fugue.deny_resource_with_message(aggregator, msg)
}

policy[p] {
	aggregator := config_aggregators[_]
	config_all_regions_enabled(aggregator)
	p = fugue.allow_resource(aggregator)
}
