package rules.azure_nsg_rdp_restricted

import data.fugue

__rego__metadoc__ := {
    "id": "7.1",
    "title": "Ensure that RDP access from the Internet is evaluated and restricted",
    "description": "Network security groups should be periodically evaluated for port misconfigurations. RDP access from the internet should be restricted to prevent unauthorized access.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_7.1"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all network security group rules
nsg_rules = fugue.resources("azurerm_network_security_rule")

# Check if rule allows RDP access from internet
is_rdp_from_internet(rule) {
    # Check for RDP port (3389)
    rule.destination_port_range == "3389"
    # Check for internet source
    rule.source_address_prefix == "*"
    # Check if rule allows access
    rule.access == "Allow"
    # Check if rule applies to inbound traffic
    rule.direction == "Inbound"
}

# Allow rules that don't permit RDP from internet
policy[p] {
    rule := nsg_rules[_]
    not is_rdp_from_internet(rule)
    p = fugue.allow_resource(rule)
}

# Deny rules that permit RDP from internet
policy[p] {
    rule := nsg_rules[_]
    is_rdp_from_internet(rule)
    p = fugue.deny_resource_with_message(rule,
        "Network security rule allows RDP access (port 3389) from internet. Remove or restrict the rule to specific IP ranges.")
}
