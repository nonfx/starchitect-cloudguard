package rules.azure_nsg_udp_access

import data.fugue

__rego__metadoc__ := {
    "id": "7.3",
    "title": "Ensure that UDP access from the Internet is evaluated and restricted",
    "description": "Network security groups should be periodically evaluated for port misconfigurations. UDP services can be exploited for DDoS amplification attacks.",
    "custom": {
        "controls": {
            "CIS-Azure_v3.0.0": ["CIS-Azure_v3.0.0_7.3"]
        },
        "severity": "High",
        "reviewer": "fugue"
    },
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_7.3"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all network security groups and their rules
nsgs = fugue.resources("azurerm_network_security_group")
nsg_rules = fugue.resources("azurerm_network_security_rule")

# Helper to check if a rule allows UDP access from internet
is_udp_internet_access(rule) {
    rule.protocol == "Udp"
    rule.direction == "Inbound"
    rule.access == "Allow"
    contains(rule.source_address_prefix, "*") # Internet source
}

# Allow NSGs with no UDP internet access rules
policy[p] {
    nsg := nsgs[_]
    count([rule | rule := nsg_rules[_]; rule.network_security_group_name == nsg.name; is_udp_internet_access(rule)]) == 0
    p = fugue.allow_resource(nsg)
}

# Deny NSGs with UDP internet access rules
policy[p] {
    nsg := nsgs[_]
    rule := nsg_rules[_]
    rule.network_security_group_name == nsg.name
    is_udp_internet_access(rule)
    p = fugue.deny_resource_with_message(nsg, sprintf("Network Security Group '%s' allows UDP access from internet through rule '%s'", [nsg.name, rule.name]))
}