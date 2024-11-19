package rules.aws_apprunner_vpc_endpoint

import data.fugue

__rego__metadoc__ := {
	"author": "sachin@nonfx.com",
	"id": "10.1",
	"title": "App Runner needs access to your application source, so it can't be encrypted. Therefore, be sure to secure the connection between your development or deployment environment and App Runner",
	"custom": {
		"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_10.1"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

apprunner_services := fugue.resources("aws_apprunner_service")

vpc_endpoints := fugue.resources("aws_vpc_endpoint")

has_apprunner_vpc_endpoint(endpoints) {
	endpoint := endpoints[_]
	endpoint.vpc_endpoint_type == "Interface"
	contains(endpoint.service_name, "apprunner")
}

apprunner_service_uses_vpc_connector(service) {
	service.network_configuration[_].egress_configuration[_].egress_type == "VPC"
}

policy[p] {
	service := apprunner_services[_]
	apprunner_service_uses_vpc_connector(service)
	has_apprunner_vpc_endpoint(vpc_endpoints)
	p = fugue.allow_resource(service)
}

policy[p] {
	service := apprunner_services[_]
	not apprunner_service_uses_vpc_connector(service)
	msg := sprintf("App Runner service '%s' is not using a VPC connector. Ensure VPC Endpoints are used for source code access.", [service.id])
	p = fugue.deny_resource_with_message(service, msg)
}

policy[p] {
	service := apprunner_services[_]
	apprunner_service_uses_vpc_connector(service)
	not has_apprunner_vpc_endpoint(vpc_endpoints)
	msg := sprintf("App Runner service '%s' is using a VPC connector, but no App Runner VPC Endpoint is defined. Ensure VPC Endpoints are used for source code access.", [service.id])
	p = fugue.deny_resource_with_message(service, msg)
}
