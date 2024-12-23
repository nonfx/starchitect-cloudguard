import { CloudWatchClient, DescribeAlarmsCommand } from '@aws-sdk/client-cloudwatch';
import { 
  CloudWatchLogsClient, 
  DescribeLogGroupsCommand,
  DescribeMetricFiltersCommand 
} from '@aws-sdk/client-cloudwatch-logs';

import {
  printSummary,
  generateSummary,
  type ComplianceReport,
  ComplianceStatus
} from '@codegen/utils/stringUtils';

const REQUIRED_PATTERN = '{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel) ||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }';

async function checkConfigChangeMonitoring(region: string = 'us-east-1'): Promise<ComplianceReport> {
  const cwClient = new CloudWatchClient({ region });
  const cwLogsClient = new CloudWatchLogsClient({ region });
  
  const results: ComplianceReport = {
    checks: [],
    metadoc: {
      title: 'Ensure AWS Config configuration changes are monitored',
      description: 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs, or an external Security information and event management (SIEM) environment, and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for detecting changes to AWS Config\'s configurations.',
      controls: [{
        id: 'CIS-AWS-Foundations-Benchmark_v3.0.0_4.9',
        document: 'CIS-AWS-Foundations-Benchmark_v3.0.0'
      }]
    }
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

      const configMetricFilter = metricFilters.metricFilters?.find(
        filter => filter.filterPattern === REQUIRED_PATTERN
      );

      if (!configMetricFilter) {
        results.checks.push({
          resourceName: logGroup.logGroupName,
          resourceArn: logGroup.arn,
          status: ComplianceStatus.FAIL,
          message: 'Log group does not have required metric filter for AWS Config changes'
        });
        continue;
      }

      // Check if metric filter has associated alarm
      const metricName = configMetricFilter.metricTransformations?.[0]?.metricName;
      if (!metricName) {
        results.checks.push({
          resourceName: logGroup.logGroupName,
          resourceArn: logGroup.arn,
          status: ComplianceStatus.FAIL,
          message: 'Metric filter does not have a metric transformation'
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
          message: 'No alarm configured for AWS Config changes metric filter'
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
      message: `Error checking CloudWatch configuration: ${error instanceof Error ? error.message : String(error)}`
    });
  }

  return results;
}

if (require.main === module) {
  const region = process.env.AWS_REGION ?? 'ap-southeast-1';
  const results = await checkConfigChangeMonitoring(region);
  printSummary(generateSummary(results));
}

export default checkConfigChangeMonitoring;