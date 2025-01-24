package rules.azure_disk_network_access

import data.fugue

__rego__metadoc__ := {
    "id": "8.5",
    "title": "Ensure Disk Network Access is not publicly accessible",
    "description": "Virtual Machine Disks and snapshots should not allow public access from all networks to maintain security.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_8.5"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all managed disks
managed_disks = fugue.resources("azurerm_managed_disk")

# Helper to check if disk has secure network access configuration
is_network_access_secure(disk) {
    disk.network_access_policy == "AllowPrivate"
    disk.public_network_access_enabled == false
}

is_network_access_secure(disk) {
    disk.network_access_policy == "DenyAll"
    disk.public_network_access_enabled == false
}

# Allow if disk has secure network access configuration
policy[p] {
    disk := managed_disks[_]
    is_network_access_secure(disk)
    p = fugue.allow_resource(disk)
}

# Deny if disk allows public access
policy[p] {
    disk := managed_disks[_]
    not is_network_access_secure(disk)
    p = fugue.deny_resource_with_message(disk, "Managed disk must not allow public network access. Configure network_access_policy to 'AllowPrivate' or 'DenyAll' and disable public_network_access_enabled")
}
