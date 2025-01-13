import { InstancesClient } from '@google-cloud/compute';
import { printSummary, generateSummary } from '../../utils/string-utils.js';
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from '../../types.js';

// Helper function to check if Confidential Computing is enabled
function isConfidentialComputingEnabled(instance: any): boolean {
  return (
    instance.confidentialInstanceConfig?.enableConfidentialCompute === true
  );
}

// Main compliance check function
export async function checkConfidentialComputing(
  projectId: string = process.env.GCP_PROJECT_ID || '',
  zone: string = process.env.GCP_ZONE || 'us-central1-a'
): Promise<ComplianceReport> {
  const client = new InstancesClient();
  const results: ComplianceReport = {
    checks: []
  };

  if (!projectId) {
    results.checks.push({
      resourceName: 'Confidential Computing Check',
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

    // Check each instance for Confidential Computing
    for (const instance of instances) {
      const instanceName = instance.name || 'Unknown Instance';
      const selfLink = instance.selfLink || undefined;

      results.checks.push({
        resourceName: instanceName,
        resourceArn: selfLink,
        status: isConfidentialComputingEnabled(instance) ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
        message: !isConfidentialComputingEnabled(instance)
          ? `Instance ${instanceName} does not have Confidential Computing enabled. Enable confidential_instance_config for enhanced data security.`
          : undefined
      });
    }
  } catch (error) {
    results.checks.push({
      resourceName: 'Confidential Computing Check',
      status: ComplianceStatus.ERROR,
      message: `Error checking Confidential Computing: ${error instanceof Error ? error.message : String(error)}`
    });
  }

  return results;
}

// Main execution if run directly
if (import.meta.main) {
  const projectId = process.env.GCP_PROJECT_ID;
  const zone = process.env.GCP_ZONE;
  const results = await checkConfidentialComputing(projectId, zone);
  printSummary(generateSummary(results));
}

// Export default with compliance check metadata
export default {
  title: 'Ensure That Compute Instances Have Confidential Computing Enabled',
  description: 'Compute instances must have Confidential Computing enabled to encrypt data during processing using AMD EPYC CPUs\'s SEV feature.',
  controls: [
    {
      id: 'CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_4.11',
      document: 'CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0'
    }
  ],
  severity: 'HIGH',
  serviceName: 'Google Compute Engine',
  shortServiceName: 'compute',
  execute: checkConfidentialComputing
} satisfies RuntimeTest;