package rules.azure_disk_auth_mode

import data.fugue

__rego__metadoc__ := {
    "id": "8.6",
    "title": "Ensure Secure Data Access Configuration for Managed Disks",
    "description": "Managed disks should be configured with private network access and proper disk access controls.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_8.6"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

managed_disks = fugue.resources("azurerm_managed_disk")
disk_access = fugue.resources("azurerm_disk_access")

is_secure_access_configured(disk) {
    disk.network_access_policy == "AllowPrivate"
    disk.public_network_access_enabled == false
    disk.disk_access_id != null
}

policy[p] {
    disk := managed_disks[_]
    is_secure_access_configured(disk)
    p = fugue.allow_resource(disk)
}

policy[p] {
    disk := managed_disks[_]
    not is_secure_access_configured(disk)
    p = fugue.deny_resource_with_message(disk, "Managed disk must be configured with private network access, disabled public access, and associated with a disk access resource")
}