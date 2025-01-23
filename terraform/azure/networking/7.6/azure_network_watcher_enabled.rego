package rules.azure_network_watcher_enabled

import data.fugue

__rego__metadoc__ := {
    "id": "7.6",
    "title": "Ensure that Network Watcher is 'Enabled' for Azure Regions that are in use",
    "description": "Enable Network Watcher for physical regions in Azure subscriptions to enable network monitoring and diagnostics.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_7.6"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all virtual networks and network watchers
vnets = fugue.resources("azurerm_virtual_network")
watchers = fugue.resources("azurerm_network_watcher")

# Get unique regions from virtual networks
vnet_regions[location] {
    vnet := vnets[_]
    location := vnet.location
}

# Check if Network Watcher exists for a region
has_watcher_for_region(region) {
    watcher := watchers[_]
    watcher.location == region
}

# Allow if Network Watcher exists for all regions with virtual networks
policy[p] {
    region := vnet_regions[_]
    has_watcher_for_region(region)
    watcher := watchers[_]
    watcher.location == region
    p = fugue.allow_resource(watcher)
}

# Deny if a region with virtual networks lacks Network Watcher
policy[p] {
    region := vnet_regions[_]
    not has_watcher_for_region(region)
    vnet := vnets[_]
    vnet.location == region
    p = fugue.deny_resource_with_message(vnet,
        sprintf("Network Watcher is not enabled for region '%s' where virtual networks exist", [region]))
}
