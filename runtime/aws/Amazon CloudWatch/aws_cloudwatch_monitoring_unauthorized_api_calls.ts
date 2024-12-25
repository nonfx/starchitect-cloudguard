import { CloudWatchClient, DescribeAlarmsCommand } from '@aws-sdk/client-cloudwatch';
import { CloudWatchLogsClient, DescribeLogGroupsCommand, DescribeMetricFiltersCommand } from '@aws-sdk/client-cloudwatch-logs';

import {
  printSummary,
  generateSummary,
} from '~codegen/utils/stringUtils';

import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

const REQUIRED_PATTERN = '{ ($.errorCode ="*UnauthorizedOperation") || ($.errorCode ="AccessDenied*") && ($.sourceIPAddress!="delivery.logs.amazonaws.com") && ($.eventName!="HeadBucket") }';

async function checkCloudWatchApiMonitoring(region: string = 'us-east-1'): Promise<ComplianceReport> {
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

      // Check metric filters for each log group
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
          message: 'Log group does not have required metric filter for unauthorized API calls'
        });
        continue;
      }

      // Check if metric filter has associated alarm
      const matchingFilter = metricFilters.metricFilters?.find(
        filter => filter.filterPattern === REQUIRED_PATTERN
      );

      if (matchingFilter?.metricTransformations?.[0]?.metricName) {
        const alarms = await cwClient.send(new DescribeAlarmsCommand({
          MetricName: matchingFilter.metricTransformations[0].metricName
        }));

        if (!alarms.MetricAlarms || alarms.MetricAlarms.length === 0) {
          results.checks.push({
            resourceName: logGroup.logGroupName,
            resourceArn: logGroup.arn,
            status: ComplianceStatus.FAIL,
            message: 'No alarm configured for unauthorized API calls metric filter'
          });
        } else {
          results.checks.push({
            resourceName: logGroup.logGroupName,
            resourceArn: logGroup.arn,
            status: ComplianceStatus.PASS,
            message: undefined
          });
        }
      }
    }

    if (results.checks.length === 0) {
      results.checks.push({
        resourceName: 'CloudWatch Configuration',
        status: ComplianceStatus.FAIL,
        message: 'No monitoring configuration found for unauthorized API calls'
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
  const results = await checkCloudWatchApiMonitoring(region);
  printSummary(generateSummary(results));
}

export default {
  title: 'Ensure unauthorized API calls are monitored',
  description: 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs, or an external Security information and event management (SIEM) environment, and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established to monitor unauthorized API calls.',
  controls: [{
    id: 'CIS-AWS-Foundations-Benchmark_v3.0.0_4.1',
    document: 'CIS-AWS-Foundations-Benchmark_v3.0.0'
  }],
  severity: 'MEDIUM',
  execute: checkCloudWatchApiMonitoring
} satisfies RuntimeTest;