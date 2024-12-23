import {
  CloudWatchLogsClient,
  DescribeMetricFiltersCommand,
} from "@aws-sdk/client-cloudwatch-logs";
import {
  CloudTrailClient,
  DescribeTrailsCommand,
} from "@aws-sdk/client-cloudtrail";

import {
  printSummary,
  generateSummary,
  type ComplianceReport,
  ComplianceStatus,
} from "@codegen/utils/stringUtils";

async function checkSecurityGroupMonitoring(
  region: string = "us-east-1"
): Promise<ComplianceReport> {
  const cloudWatchLogsClient = new CloudWatchLogsClient({ region });
  const cloudTrailClient = new CloudTrailClient({ region });
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
    // Check CloudTrail configuration
    const trailsResponse = await cloudTrailClient.send(
      new DescribeTrailsCommand({})
    );
    const trails = trailsResponse.trailList || [];

    if (trails.length === 0) {
      results.checks.push({
        resourceName: "CloudTrail",
        status: ComplianceStatus.FAIL,
        message: "No CloudTrail trails configured",
      });
      return results;
    }

    let hasValidTrail = false;
    let cloudWatchLogGroup = "";

    // Check each trail for proper configuration
    for (const trail of trails) {
      if (
        trail.IsMultiRegionTrail &&
        trail.CloudWatchLogsLogGroupArn &&
        trail.CloudWatchLogsRoleArn
      ) {
        hasValidTrail = true;
        cloudWatchLogGroup =
          trail.CloudWatchLogsLogGroupArn.split(":log-group:")[1].split(":")[0];
        break;
      }
    }

    if (!hasValidTrail) {
      results.checks.push({
        resourceName: "CloudTrail",
        status: ComplianceStatus.FAIL,
        message:
          "No properly configured CloudTrail found with CloudWatch Logs integration",
      });
      return results;
    }

    // Check for security group metric filter
    const metricFiltersResponse = await cloudWatchLogsClient.send(
      new DescribeMetricFiltersCommand({
        logGroupName: cloudWatchLogGroup,
      })
    );

    const securityGroupPattern =
      "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }";

    const hasSecurityGroupFilter = metricFiltersResponse.metricFilters?.some(
      (filter) => filter.filterPattern === securityGroupPattern
    );

    if (!hasSecurityGroupFilter) {
      results.checks.push({
        resourceName: cloudWatchLogGroup,
        status: ComplianceStatus.FAIL,
        message: "No metric filter found for security group changes",
      });
      return results;
    }

    results.checks.push({
      resourceName: cloudWatchLogGroup,
      status: ComplianceStatus.PASS,
      message: "Security group changes are being monitored",
    });
  } catch (error) {
    results.checks.push({
      resourceName: "Monitoring Check",
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
