import { CloudWatchClient, GetMetricDataCommand } from '@aws-sdk/client-cloudwatch';
import { CloudWatchLogsClient, DescribeLogGroupsCommand, DescribeMetricFiltersCommand } from '@aws-sdk/client-cloudwatch-logs';

import {
  printSummary,
  generateSummary,
  type ComplianceReport,
  ComplianceStatus
} from '@codegen/utils/stringUtils';

const REQUIRED_PATTERN = '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }';

async function checkVpcChangesMonitored(region: string = 'us-east-1'): Promise<ComplianceReport> {
  const cwClient = new CloudWatchClient({ region });
  const cwLogsClient = new CloudWatchLogsClient({ region });
  
  const results: ComplianceReport = {
    checks: [],
    metadoc: {
      title: 'Ensure VPC changes are monitored',
      description: 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs, or an external Security information and event management (SIEM) environment, and establishing corresponding metric filters and alarms. It is possible to have more than 1 VPC within an account, in addition it is also possible to create a peer connection between 2 VPCs enabling network traffic to route between VPCs. It is recommended that a metric filter and alarm be established for changes made to VPCs.',
      controls: [
        {
          id: 'CIS-AWS-Foundations-Benchmark_v3.0.0_4.14',
          document: 'CIS-AWS-Foundations-Benchmark_v3.0.0'
        }
      ]
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

      const vpcMetricFilter = metricFilters.metricFilters?.find(
        filter => filter.filterPattern === REQUIRED_PATTERN
      );

      if (!vpcMetricFilter) {
        results.checks.push({
          resourceName: logGroup.logGroupName,
          resourceArn: logGroup.arn,
          status: ComplianceStatus.FAIL,
          message: 'Log group does not have required VPC changes metric filter'
        });
        continue;
      }

      // Check if metric has data (indicating active monitoring)
      const metricName = vpcMetricFilter.metricTransformations?.[0]?.metricName;
      if (!metricName) {
        results.checks.push({
          resourceName: logGroup.logGroupName,
          resourceArn: logGroup.arn,
          status: ComplianceStatus.FAIL,
          message: 'Metric filter does not have a metric transformation'
        });
        continue;
      }

      const now = new Date();
      const startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000); // 24 hours ago

      const metricData = await cwClient.send(new GetMetricDataCommand({
        StartTime: startTime,
        EndTime: now,
        MetricDataQueries: [{
          Id: 'm1',
          MetricStat: {
            Metric: {
              MetricName: metricName,
              Namespace: vpcMetricFilter.metricTransformations[0].metricNamespace || 'CloudTrail'
            },
            Period: 3600,
            Stat: 'Sum'
          }
        }]
      }));

      if (!metricData.MetricDataResults?.[0]?.Values?.length) {
        results.checks.push({
          resourceName: logGroup.logGroupName,
          resourceArn: logGroup.arn,
          status: ComplianceStatus.FAIL,
          message: 'No metric data found for VPC changes monitoring'
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
      message: `Error checking VPC monitoring: ${error instanceof Error ? error.message : String(error)}`
    });
  }

  return results;
}

if (require.main === module) {
  const region = process.env.AWS_REGION ?? 'ap-southeast-1';
  const results = await checkVpcChangesMonitored(region);
  printSummary(generateSummary(results));
}

export default checkVpcChangesMonitored;