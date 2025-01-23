package rules.azure_sql_audit_retention

import data.fugue

__rego__metadoc__ := {
    "id": "5.1.6",
    "title": "Ensure that 'Auditing' Retention is 'greater than 90 days'",
    "description": "SQL Server Audit Retention should be configured to be greater than 90 days to maintain comprehensive audit logs for security analysis and compliance requirements.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_5.1.6"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all SQL server extended audit policies
audit_policies = fugue.resources("azurerm_mssql_server_extended_auditing_policy")

# Helper to check if retention period is compliant
is_compliant_retention(policy) {
    policy.retention_in_days > 90
}

is_compliant_retention(policy) {
    policy.retention_in_days == 0  # 0 means unlimited retention
}

# Allow policies with compliant retention period
policy[p] {
    policy := audit_policies[_]
    is_compliant_retention(policy)
    p = fugue.allow_resource(policy)
}

# Deny policies with insufficient retention period
policy[p] {
    policy := audit_policies[_]
    not is_compliant_retention(policy)
    p = fugue.deny_resource_with_message(policy, "SQL Server audit retention period must be greater than 90 days or set to 0 for unlimited retention")
}