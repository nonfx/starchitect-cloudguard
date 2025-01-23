package rules.azure_sql_no_public_access

import data.fugue

__rego__metadoc__ := {
    "id": "5.1.2",
    "title": "Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)",
    "description": "Ensure that no SQL Databases allow ingress from 0.0.0.0/0 (ANY IP). SQL Server firewall rules should be configured with specific IP ranges to prevent unauthorized access.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_5.1.2"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all SQL Server firewall rules
firewall_rules = fugue.resources("azurerm_sql_firewall_rule")

# Helper to check if rule allows public access
is_public_access(rule) {
    rule.start_ip_address == "0.0.0.0"
    rule.end_ip_address == "0.0.0.0"
}

is_public_access(rule) {
    rule.start_ip_address == "0.0.0.0"
    rule.end_ip_address == "255.255.255.255"
}

# Allow rules that don't permit public access
policy[p] {
    rule := firewall_rules[_]
    not is_public_access(rule)
    p = fugue.allow_resource(rule)
}

# Deny rules that permit public access
policy[p] {
    rule := firewall_rules[_]
    is_public_access(rule)
    p = fugue.deny_resource_with_message(rule, "SQL Server firewall rule allows access from 0.0.0.0/0. Configure specific IP ranges instead.")
}