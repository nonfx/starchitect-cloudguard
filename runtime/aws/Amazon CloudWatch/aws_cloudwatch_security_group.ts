import {
  CloudWatchClient,
  DescribeAlarmsCommand,
} from "@aws-sdk/client-cloudwatch";
import {
  CloudWatchLogsClient,
  DescribeLogGroupsCommand,
  DescribeMetricFiltersCommand,
} from "@aws-sdk/client-cloudwatch-logs";

import {
  printSummary,
  generateSummary,
  type ComplianceReport,
  ComplianceStatus,
} from "@codegen/utils/stringUtils";

const REQUIRED_PATTERN =
  "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }";

async function checkSecurityGroupMonitoring(
  region: string = "us-east-1"
): Promise<ComplianceReport> {
  const cwClient = new CloudWatchClient({ region });
  const cwLogsClient = new CloudWatchLogsClient({ region });

  const results: ComplianceReport = {
    checks: [],
    metadoc: {
      title: "Ensure security group changes are monitored",
      description:
        "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs, or an external Security information and event management (SIEM) environment, and establishing corresponding metric filters and alarms. Security Groups are a stateful packet filter that controls ingress and egress traffic within a VPC.",
      controls: [
        {
          id: "CIS-AWS-Foundations-Benchmark_v3.0.0_4.10",
          document: "CIS-AWS-Foundations-Benchmark_v3.0.0",
        },
      ],
    },
  };

  try {
    const logGroups = await cwLogsClient.send(new DescribeLogGroupsCommand({}));

    if (!logGroups.logGroups || logGroups.logGroups.length === 0) {
      results.checks.push({
        resourceName: "CloudWatch Logs",
        status: ComplianceStatus.FAIL,
        message: "No CloudWatch Log Groups found",
      });
      return results;
    }

    for (const logGroup of logGroups.logGroups) {
      if (!logGroup.logGroupName) continue;

      const metricFilters = await cwLogsClient.send(
        new DescribeMetricFiltersCommand({
          logGroupName: logGroup.logGroupName,
        })
      );

      const matchingFilter = metricFilters.metricFilters?.find(
        (filter) => filter.filterPattern === REQUIRED_PATTERN
      );

      if (!matchingFilter) {
        results.checks.push({
          resourceName: logGroup.logGroupName,
          resourceArn: logGroup.arn,
          status: ComplianceStatus.FAIL,
          message:
            "Log group does not have required security group changes metric filter",
        });
        continue;
      }

      if (matchingFilter.metricTransformations?.[0]?.metricName) {
        const alarms = await cwClient.send(
          new DescribeAlarmsCommand({
            AlarmNames: [],
            MetricName: matchingFilter.metricTransformations[0].metricName,
          })
        );

        if (!alarms.MetricAlarms || alarms.MetricAlarms.length === 0) {
          results.checks.push({
            resourceName: logGroup.logGroupName,
            resourceArn: logGroup.arn,
            status: ComplianceStatus.FAIL,
            message:
              "No alarm configured for security group changes metric filter",
          });
        } else {
          results.checks.push({
            resourceName: logGroup.logGroupName,
            resourceArn: logGroup.arn,
            status: ComplianceStatus.PASS,
            message: undefined,
          });
        }
      }
    }

    if (results.checks.length === 0) {
      results.checks.push({
        resourceName: "CloudWatch Configuration",
        status: ComplianceStatus.FAIL,
        message: "No monitoring configuration found for security group changes",
      });
    }
  } catch (error) {
    results.checks.push({
      resourceName: "CloudWatch",
      status: ComplianceStatus.ERROR,
      message: `Error checking security group monitoring: ${
        error instanceof Error ? error.message : String(error)
      }`,
    });
  }

  return results;
}

if (require.main === module) {
  const region = process.env.AWS_REGION ?? "ap-southeast-1";
  const results = await checkSecurityGroupMonitoring(region);
  printSummary(generateSummary(results));
}

export default checkSecurityGroupMonitoring;
