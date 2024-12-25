import {
  CloudWatchClient,
  GetMetricDataCommand,
  DescribeAlarmsCommand
} from '@aws-sdk/client-cloudwatch';

import {
  CloudWatchLogsClient,
  DescribeMetricFiltersCommand,
  DescribeLogGroupsCommand
} from '@aws-sdk/client-cloudwatch-logs';

import {
  printSummary,
  generateSummary
} from '~codegen/utils/stringUtils';

import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

const REQUIRED_PATTERN = '{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}';

async function checkIamPolicyMonitoring(
  region: string = 'us-east-1'
): Promise<ComplianceReport> {
  const cloudwatchClient = new CloudWatchClient({ region });
  const logsClient = new CloudWatchLogsClient({ region });
  const results: ComplianceReport = {
    checks: []
  };

  try {
    // Get all log groups
    const logGroups = await logsClient.send(new DescribeLogGroupsCommand({}));

    if (!logGroups.logGroups || logGroups.logGroups.length === 0) {
      results.checks.push({
        resourceName: 'CloudWatch Logs',
        status: ComplianceStatus.FAIL,
        message: 'No CloudWatch log groups found'
      });
      return results;
    }

    for (const logGroup of logGroups.logGroups) {
      if (!logGroup.logGroupName) continue;

      // Check metric filters for each log group
      const metricFilters = await logsClient.send(new DescribeMetricFiltersCommand({
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
          message: 'Log group does not have required IAM policy change metric filter'
        });
        continue;
      }

      // Check if metric filter has associated alarm
      const matchingFilter = metricFilters.metricFilters?.find(
        filter => filter.filterPattern === REQUIRED_PATTERN
      );

      if (matchingFilter?.metricTransformations?.[0]?.metricName) {
        const alarms = await cloudwatchClient.send(new DescribeAlarmsCommand({
          MetricName: matchingFilter.metricTransformations[0].metricName
        }));

        if (!alarms.MetricAlarms || alarms.MetricAlarms.length === 0) {
          results.checks.push({
            resourceName: logGroup.logGroupName,
            resourceArn: logGroup.arn,
            status: ComplianceStatus.FAIL,
            message: 'No alarm configured for IAM policy change metric filter'
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

  } catch (error) {
    results.checks.push({
      resourceName: 'CloudWatch',
      status: ComplianceStatus.ERROR,
      message: `Error checking CloudWatch configuration: ${error instanceof Error ? error.message : String(error)}`
    });
  }

  return results;
}

if (require.main === module) {
  const region = process.env.AWS_REGION ?? 'ap-southeast-1';
  const results = await checkIamPolicyMonitoring(region);
  printSummary(generateSummary(results));
}

export default {
  title: 'Ensure IAM policy changes are monitored',
  description: 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs, or an external Security information and event management (SIEM) environment, and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established changes made to Identity and Access Management (IAM) policies.',
  controls: [{
    id: 'CIS-AWS-Foundations-Benchmark_v3.0.0_4.4',
    document: 'CIS-AWS-Foundations-Benchmark_v3.0.0'
  }],
  severity: 'MEDIUM',
  execute: checkIamPolicyMonitoring
} satisfies RuntimeTest;