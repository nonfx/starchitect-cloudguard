package rules.ecs_fargate_latest_platform_version

import data.fugue

__rego__metadoc__ := {
	"id": "ECS.10",
	"title": "ECS Fargate services should run on the latest Fargate platform version",
	"description": "ECS Fargate services must run on the latest platform version (Linux 1.4.0 or Windows 1.0.0) to ensure security updates.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_ECS.10"]}, "severity": "Medium", "author": "llmagent", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

# Get all ECS services
ecs_services = fugue.resources("aws_ecs_service")

# Latest platform versions
latest_versions = {
	"LINUX": ["1.4.0", "LATEST"],
	"WINDOWS": ["1.0.0"],
}

is_latest_version(platform_version) {
	platform_version == latest_versions.LINUX[_]
}

is_latest_version(platform_version) {
	platform_version == latest_versions.WINDOWS[_]
}

# Policy rules
policy[p] {
	service := ecs_services[_]
	service.launch_type == "FARGATE"
	is_latest_version(service)
	p = fugue.allow_resource(service)
}

policy[p] {
	service := ecs_services[_]
	service.launch_type == "FARGATE"
	not is_latest_version(service)
	p = fugue.deny_resource_with_message(
		service,
		sprintf("ECS Fargate service is not running on the latest platform version. Current version: %s", [service.platform_version]),
	)
}
