package rules.azure_nsg_ssh_access

import data.fugue

__rego__metadoc__ := {
    "id": "7.2",
    "title": "Ensure that SSH access from the Internet is evaluated and restricted",
    "description": "Network security groups should be periodically evaluated for port misconfigurations and SSH access from the Internet should be restricted.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_7.2"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all network security groups and their rules
nsgs = fugue.resources("azurerm_network_security_group")
nsg_rules = fugue.resources("azurerm_network_security_rule")

# Helper to check if a rule allows SSH from internet
is_ssh_open_to_internet(rule) {
    # Check if rule is for SSH port
    contains(rule.destination_port_range, "22")
    # Check if source is internet
    rule.source_address_prefix == "*"
    # Check if rule allows access
    rule.access == "Allow"
    # Check if rule is for inbound traffic
    rule.direction == "Inbound"
}

# Allow NSGs with no open SSH access
policy[p] {
    nsg := nsgs[_]
    count([rule | rule = nsg_rules[_]; is_ssh_open_to_internet(rule)]) == 0
    p = fugue.allow_resource(nsg)
}

# Deny NSGs with open SSH access
policy[p] {
    nsg := nsgs[_]
    rule := nsg_rules[_]
    is_ssh_open_to_internet(rule)
    p = fugue.deny_resource_with_message(nsg, "Network Security Group allows SSH access (port 22) from the Internet. Restrict SSH access to specific IP ranges or use VPN/ExpressRoute for secure access.")
}
