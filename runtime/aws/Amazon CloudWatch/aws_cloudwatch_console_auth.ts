import { CloudWatchClient, DescribeAlarmsCommand } from '@aws-sdk/client-cloudwatch';
import { CloudWatchLogsClient, DescribeLogGroupsCommand, DescribeMetricFiltersCommand } from '@aws-sdk/client-cloudwatch-logs';

import {
  printSummary,
  generateSummary,
} from '~codegen/utils/stringUtils';

import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

const REQUIRED_PATTERN = '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }';

async function checkConsoleAuthMonitoring(region: string = 'us-east-1'): Promise<ComplianceReport> {
  const cwClient = new CloudWatchClient({ region });
  const cwLogsClient = new CloudWatchLogsClient({ region });
  const results: ComplianceReport = {
    checks: []
  };

  try {
    // Get all log groups
    const logGroups = await cwLogsClient.send(new DescribeLogGroupsCommand({}));

    if (!logGroups.logGroups || logGroups.logGroups.length === 0) {
      results.checks.push({
        resourceName: 'CloudWatch Logs',
        status: ComplianceStatus.FAIL,
        message: 'No CloudWatch Log Groups found'
      });
      return results;
    }

    for (const logGroup of logGroups.logGroups) {
      if (!logGroup.logGroupName) continue;

      // Check metric filters for each log group using CloudWatch Logs client
      const metricFilters = await cwLogsClient.send(new DescribeMetricFiltersCommand({
        logGroupName: logGroup.logGroupName
      }));

      const hasRequiredFilter = metricFilters.metricFilters?.some(
        filter => filter.filterPattern === REQUIRED_PATTERN
      );

      if (!hasRequiredFilter) {
        results.checks.push({
          resourceName: logGroup.logGroupName,
          resourceArn: logGroup.arn,
          status: ComplianceStatus.FAIL,
          message: 'Log group does not have required metric filter for console authentication failures'
        });
        continue;
      }

      // Check if metric filter has associated alarm
      const relevantFilter = metricFilters.metricFilters?.find(
        filter => filter.filterPattern === REQUIRED_PATTERN
      );

      if (relevantFilter?.metricTransformations?.[0]?.metricName) {
        const alarms = await cwClient.send(new DescribeAlarmsCommand({
          MetricName: relevantFilter.metricTransformations[0].metricName
        }));

        if (!alarms.MetricAlarms || alarms.MetricAlarms.length === 0) {
          results.checks.push({
            resourceName: logGroup.logGroupName,
            resourceArn: logGroup.arn,
            status: ComplianceStatus.FAIL,
            message: 'No alarm configured for console authentication failures metric filter'
          });
          continue;
        }

        results.checks.push({
          resourceName: logGroup.logGroupName,
          resourceArn: logGroup.arn,
          status: ComplianceStatus.PASS,
          message: undefined
        });
      }
    }

    if (results.checks.length === 0) {
      results.checks.push({
        resourceName: 'CloudWatch Configuration',
        status: ComplianceStatus.FAIL,
        message: 'No monitoring configuration found for console authentication failures'
      });
    }
  } catch (error) {
    results.checks.push({
      resourceName: 'CloudWatch Check',
      status: ComplianceStatus.ERROR,
      message: `Error checking CloudWatch configuration: ${error instanceof Error ? error.message : String(error)}`
    });
  }

  return results;
}

if (require.main === module) {
  const region = process.env.AWS_REGION ?? 'ap-southeast-1';
  const results = await checkConsoleAuthMonitoring(region);
  printSummary(generateSummary(results));
}

export default {
  title: 'Ensure AWS Management Console authentication failures are monitored',
  description: 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs, or an external Security information and event management (SIEM) environment, and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for failed console authentication attempts.',
  controls: [{
    id: 'CIS-AWS-Foundations-Benchmark_v3.0.0_4.6',
    document: 'CIS-AWS-Foundations-Benchmark_v3.0.0'
  }],
  severity: 'MEDIUM',
  execute: checkConsoleAuthMonitoring
} satisfies RuntimeTest;

