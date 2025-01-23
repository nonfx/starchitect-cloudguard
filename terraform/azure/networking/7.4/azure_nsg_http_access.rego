package rules.azure_nsg_http_access

import data.fugue

__rego__metadoc__ := {
    "id": "7.4",
    "title": "Ensure that HTTP(S) access from the Internet is evaluated and restricted",
    "description": "Network security groups should be periodically evaluated for port misconfigurations and HTTP(S) access should be restricted from the Internet.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_7.4"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all network security groups and their rules
nsgs = fugue.resources("azurerm_network_security_group")
nsg_rules = fugue.resources("azurerm_network_security_rule")

# Helper function to check if a port range includes HTTP/HTTPS ports
contains_http_ports(port_range) {
    ports = split(port_range, "-")
    count(ports) == 2
    to_number(ports[0]) <= 80
    to_number(ports[1]) >= 80
}

contains_http_ports(port_range) {
    ports = split(port_range, "-")
    count(ports) == 2
    to_number(ports[0]) <= 443
    to_number(ports[1]) >= 443
}

contains_http_ports(port_range) {
    port_range == "80"
}

contains_http_ports(port_range) {
    port_range == "443"
}

contains_http_ports(port_range) {
    port_range == "*"
}

# Check if a rule allows unrestricted HTTP(S) access
is_unrestricted_http_access(rule) {
    # Check if rule is for inbound traffic
    rule.direction == "Inbound"

    # Check if rule allows traffic
    rule.access == "Allow"

    # Check if source is unrestricted
    source_prefix := rule.source_address_prefix
    any([
        source_prefix == "*",
        source_prefix == "Internet",
        source_prefix == "0.0.0.0/0"
    ])

    # Check for HTTP/HTTPS ports
    contains_http_ports(rule.destination_port_range)
}

# Allow NSGs with no unrestricted HTTP(S) access
policy[p] {
    nsg := nsgs[_]
    not has_unrestricted_access(nsg)
    p = fugue.allow_resource(nsg)
}

# Deny NSGs with unrestricted HTTP(S) access
policy[p] {
    nsg := nsgs[_]
    has_unrestricted_access(nsg)
    p = fugue.deny_resource_with_message(nsg,
        "Network Security Group allows unrestricted HTTP(S) access from the Internet")
}

# Helper function to check if NSG has unrestricted access
has_unrestricted_access(nsg) {
    rule := nsg_rules[_]
    rule.network_security_group_name == nsg.name
    rule.resource_group_name == nsg.resource_group_name
    is_unrestricted_http_access(rule)
}
