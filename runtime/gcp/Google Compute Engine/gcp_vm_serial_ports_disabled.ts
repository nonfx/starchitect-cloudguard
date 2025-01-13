import { InstancesClient } from '@google-cloud/compute';
import { printSummary, generateSummary } from '../../utils/string-utils.js';
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from '../../types.js';

// Helper function to check if serial ports are enabled
function isSerialPortEnabled(instance: any): boolean {
  return instance.metadata?.items?.some(
    (item: any) => 
      item.key === 'serial-port-enable' && 
      item.value?.toUpperCase() === 'TRUE'
  ) ?? false;
}

// Main compliance check function
export async function checkVMSerialPorts(
  projectId: string = process.env.GCP_PROJECT_ID || '',
  zone: string = process.env.GCP_ZONE || 'us-central1-a'
): Promise<ComplianceReport> {
  const client = new InstancesClient();
  const results: ComplianceReport = {
    checks: []
  };

  if (!projectId) {
    results.checks.push({
      resourceName: 'VM Serial Ports Check',
      status: ComplianceStatus.ERROR,
      message: 'Project ID is not provided'
    });
    return results;
  }

  try {
    // List all compute instances in the specified zone
    const [instances] = await client.list({
      project: projectId,
      zone
    });

    // No instances found
    if (!instances || instances.length === 0) {
      results.checks.push({
        resourceName: 'GCP Compute Instances',
        status: ComplianceStatus.NOTAPPLICABLE,
        message: `No compute instances found in zone ${zone}`
      });
      return results;
    }

    // Check each instance for serial port configuration
    for (const instance of instances) {
      const instanceName = instance.name || 'Unknown Instance';
      const selfLink = instance.selfLink || undefined;

      results.checks.push({
        resourceName: instanceName,
        resourceArn: selfLink,
        status: isSerialPortEnabled(instance) ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
        message: isSerialPortEnabled(instance)
          ? `Instance ${instanceName} has serial port access enabled. This allows unrestricted connections and should be disabled.`
          : undefined
      });
    }
  } catch (error) {
    results.checks.push({
      resourceName: 'VM Serial Ports Check',
      status: ComplianceStatus.ERROR,
      message: `Error checking VM serial ports: ${error instanceof Error ? error.message : String(error)}`
    });
  }

  return results;
}

// Main execution if run directly
if (import.meta.main) {
  const projectId = process.env.GCP_PROJECT_ID;
  const zone = process.env.GCP_ZONE;
  const results = await checkVMSerialPorts(projectId, zone);
  printSummary(generateSummary(results));
}

// Export default with compliance check metadata
export default {
  title: "Ensure 'Enable Connecting to Serial Ports' Is Not Enabled for VM Instance",
  description: "VM instances should not have serial port access enabled as it allows connections from any IP address without IP-based restrictions.",
  controls: [
    {
      id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_4.5",
      document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
    }
  ],
  severity: "HIGH",
  serviceName: "Google Compute Engine",
  shortServiceName: "compute",
  execute: checkVMSerialPorts
} satisfies RuntimeTest;