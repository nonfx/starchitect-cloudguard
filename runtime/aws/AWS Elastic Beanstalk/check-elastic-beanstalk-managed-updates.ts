import { ElasticBeanstalkClient, DescribeEnvironmentsCommand, DescribeConfigurationSettingsCommand } from '@aws-sdk/client-elastic-beanstalk';
import { printSummary, generateSummary } from '../../utils/string-utils.js';
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from '../../types.js';

async function checkManagedUpdatesCompliance(region: string = 'us-east-1'): Promise<ComplianceReport> {
  const client = new ElasticBeanstalkClient({ region });
  const results: ComplianceReport = {
    checks: []
  };

  try {
    // Get all Elastic Beanstalk environments
    const environments = await client.send(new DescribeEnvironmentsCommand({}));

    if (!environments.Environments || environments.Environments.length === 0) {
      results.checks = [{
        resourceName: 'No Elastic Beanstalk Environments',
        status: ComplianceStatus.NOTAPPLICABLE,
        message: 'No Elastic Beanstalk environments found in the region'
      }];
      return results;
    }

    // Check each environment for managed updates configuration
    for (const env of environments.Environments) {
      if (!env.EnvironmentName || !env.EnvironmentId) {
        results.checks.push({
          resourceName: 'Unknown Environment',
          status: ComplianceStatus.ERROR,
          message: 'Environment found without name or ID'
        });
        continue;
      }

      try {
        const configSettings = await client.send(new DescribeConfigurationSettingsCommand({
          EnvironmentName: env.EnvironmentName,
          ApplicationName: env.ApplicationName
        }));

        const managedActionsEnabled = configSettings.ConfigurationSettings?.[0]?.OptionSettings?.some(
          setting => 
            setting.OptionName === 'ManagedActionsEnabled' && 
            setting.Value?.toLowerCase() === 'true'
        );

        results.checks.push({
          resourceName: env.EnvironmentName,
          resourceArn: env.EnvironmentArn,
          status: managedActionsEnabled ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
          message: managedActionsEnabled ? 
            undefined : 
            'Managed Platform updates is not configured for this Elastic Beanstalk environment'
        });
      } catch (error) {
        results.checks.push({
          resourceName: env.EnvironmentName,
          resourceArn: env.EnvironmentArn,
          status: ComplianceStatus.ERROR,
          message: `Error checking configuration settings: ${error instanceof Error ? error.message : String(error)}`
        });
      }
    }
  } catch (error) {
    results.checks = [{
      resourceName: 'Region Check',
      status: ComplianceStatus.ERROR,
      message: `Error checking Elastic Beanstalk environments: ${error instanceof Error ? error.message : String(error)}`
    }];
    return results;
  }

  return results;
}

if (import.meta.main) {
  const region = process.env.AWS_REGION;
  const results = await checkManagedUpdatesCompliance(region);
  printSummary(generateSummary(results));
}

export default {
  title: 'Ensure Managed Platform updates is configured',
  description: 'AWS Elastic Beanstalk regularly releases platform updates to provide fixes, software updates, and new features. With managed platform updates, you can configure your environment to automatically upgrade to the latest version of a platform during a scheduled maintenance window. Your application remains in service during the update process with no reduction in capacity. Managed updates are available on both single-instance and load-balanced environments. They also ensure you aren\'t introducing any vulnerabilities by running legacy systems that require updates and patches.',
  controls: [{
    id: 'CIS-AWS-Compute-Services-Benchmark_v1.0.0_6.1',
    document: 'CIS-AWS-Compute-Services-Benchmark_v1.0.0'
  }],
  severity: 'MEDIUM',
  execute: checkManagedUpdatesCompliance
} satisfies RuntimeTest;