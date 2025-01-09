import { CloudFormationClient, DescribeStacksCommand } from '@aws-sdk/client-cloudformation';
import { printSummary, generateSummary } from '../../utils/string-utils.js';
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from '../../types.js';

async function checkCloudFormationStackNotifications(
  region: string = 'us-east-1'
): Promise<ComplianceReport> {
  const client = new CloudFormationClient({ region });
  const results: ComplianceReport = {
    checks: []
  };

  try {
    let nextToken: string | undefined;
    let stackFound = false;

    do {
      const command = new DescribeStacksCommand({
        NextToken: nextToken
      });

      const response = await client.send(command);

      if (!response.Stacks || response.Stacks.length === 0) {
        if (!stackFound) {
          results.checks = [
            {
              resourceName: 'No CloudFormation Stacks',
              status: ComplianceStatus.NOTAPPLICABLE,
              message: 'No CloudFormation stacks found in the region'
            }
          ];
          return results;
        }
        break;
      }

      for (const stack of response.Stacks) {
        stackFound = true;

        if (!stack.StackName) {
          results.checks.push({
            resourceName: 'Unknown Stack',
            status: ComplianceStatus.ERROR,
            message: 'Stack found without name'
          });
          continue;
        }

        const hasNotifications = stack.NotificationARNs && stack.NotificationARNs.length > 0;

        results.checks.push({
          resourceName: stack.StackName,
          resourceArn: stack.StackId,
          status: hasNotifications ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
          message: hasNotifications
            ? undefined
            : 'CloudFormation stack does not have SNS notifications configured'
        });
      }

      nextToken = response.NextToken;
    } while (nextToken);
  } catch (error) {
    results.checks = [
      {
        resourceName: 'CloudFormation Check',
        status: ComplianceStatus.ERROR,
        message: `Error checking CloudFormation stacks: ${error instanceof Error ? error.message : String(error)}`
      }
    ];
    return results;
  }

  return results;
}

if (import.meta.main) {
  const region = process.env.AWS_REGION;
  const results = await checkCloudFormationStackNotifications(region);
  printSummary(generateSummary(results));
}

export default {
  title: 'CloudFormation stacks should be integrated with Simple Notification Service (SNS)',
  description: 'This control checks whether an Amazon Simple Notification Service notification is integrated with an AWS CloudFormation stack. The control fails for a CloudFormation stack if no SNS notification is associated with it.Configuring an SNS notification with your CloudFormation stack helps immediately notify stakeholders of any events or changes occurring with the stack',
  controls: [
    {
      id: 'AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFormation.1',
      document: 'AWS-Foundational-Security-Best-Practices_v1.0.0'
    }
  ],
  severity: 'LOW',
  execute: checkCloudFormationStackNotifications,
  serviceName: 'AWS CloudFormation',
  shortServiceName: 'cloudformation'
} satisfies RuntimeTest;