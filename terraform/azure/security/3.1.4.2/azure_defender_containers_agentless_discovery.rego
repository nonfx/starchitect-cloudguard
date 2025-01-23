package rules.azure_defender_containers_agentless_discovery

import data.fugue

__rego__metadoc__ := {
    "id": "3.1.4.2",
    "title": "Ensure that 'Agentless discovery for Kubernetes' component status 'On'",
    "description": "Enable automatic discovery and configuration scanning of the Microsoft Kubernetes clusters.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.1.4.2"]},"severity":"High"},
}

resource_type := "MULTIPLE"

security_center_subs = fugue.resources("azurerm_security_center_subscription_pricing")

is_agentless_discovery_enabled(sub) {
    sub.resource_type == "ContainerRegistry"
    sub.tier == "Standard"
    sub.extension[_].name == "AgentlessDiscoveryForKubernetes"
}

policy[p] {
    sub := security_center_subs[_]
    is_agentless_discovery_enabled(sub)
    p = fugue.allow_resource(sub)
}

policy[p] {
    sub := security_center_subs[_]
    not is_agentless_discovery_enabled(sub)
    p = fugue.deny_resource_with_message(sub, "Agentless discovery for Kubernetes must be enabled in Microsoft Defender for Containers")
}

policy[p] {
    count(security_center_subs) == 0
    p = fugue.missing_resource_with_message("azurerm_security_center_subscription_pricing", "No Microsoft Defender for Containers configuration found")
}