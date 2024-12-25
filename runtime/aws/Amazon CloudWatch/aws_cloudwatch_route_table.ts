import { CloudWatchClient, DescribeAlarmsCommand } from '@aws-sdk/client-cloudwatch';
import { CloudWatchLogsClient, DescribeLogGroupsCommand, DescribeMetricFiltersCommand } from '@aws-sdk/client-cloudwatch-logs';

import {
  printSummary,
  generateSummary,
} from '~codegen/utils/stringUtils';

import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

const REQUIRED_PATTERN = '{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }';

async function checkRouteTableMonitoring(region: string = 'us-east-1'): Promise<ComplianceReport> {
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
        message: 'No CloudWatch log groups found'
      });
      return results;
    }

    for (const logGroup of logGroups.logGroups) {
      if (!logGroup.logGroupName) continue;

      // Check metric filters for each log group
      const metricFilters = await cwLogsClient.send(new DescribeMetricFiltersCommand({
        logGroupName: logGroup.logGroupName
      }));

      const routeTableFilter = metricFilters.metricFilters?.find(
        filter => filter.filterPattern === REQUIRED_PATTERN
      );

      if (!routeTableFilter) {
        results.checks.push({
          resourceName: logGroup.logGroupName,
          resourceArn: logGroup.arn,
          status: ComplianceStatus.FAIL,
          message: 'Log group does not have required route table monitoring metric filter'
        });
        continue;
      }

      // Check if metric filter has associated alarm
      const metricName = routeTableFilter.metricTransformations?.[0]?.metricName;
      if (!metricName) {
        results.checks.push({
          resourceName: logGroup.logGroupName,
          resourceArn: logGroup.arn,
          status: ComplianceStatus.FAIL,
          message: 'Metric filter does not have metric transformation configured'
        });
        continue;
      }

      const alarms = await cwClient.send(new DescribeAlarmsCommand({
        MetricName: metricName
      }));

      if (!alarms.MetricAlarms || alarms.MetricAlarms.length === 0) {
        results.checks.push({
          resourceName: logGroup.logGroupName,
          resourceArn: logGroup.arn,
          status: ComplianceStatus.FAIL,
          message: 'No alarms configured for route table monitoring metric'
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
  } catch (error) {
    results.checks.push({
      resourceName: 'CloudWatch',
      status: ComplianceStatus.ERROR,
      message: `Error checking route table monitoring: ${error instanceof Error ? error.message : String(error)}`
    });
  }

  return results;
}

if (require.main === module) {
  const region = process.env.AWS_REGION ?? 'ap-southeast-1';
  const results = await checkRouteTableMonitoring(region);
  printSummary(generateSummary(results));
}

export default {
  title: 'Ensure route table changes are monitored',
  description: 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs, or an external Security information and event management (SIEM) environment, and establishing corresponding metric filters and alarms. Routing tables are used to route network traffic between subnets and to network gateways. It is recommended that a metric filter and alarm be established for changes to route tables.',
  controls: [{
    id: 'CIS-AWS-Foundations-Benchmark_v3.0.0_4.13',
    document: 'CIS-AWS-Foundations-Benchmark_v3.0.0'
  }],
  severity: 'MEDIUM',
  execute: checkRouteTableMonitoring
} satisfies RuntimeTest;