import { EC2Client, DescribeInstancesCommand } from '@aws-sdk/client-ec2';
import { printSummary, generateSummary, ComplianceStatus, type ComplianceReport } from '@codegen/utils/stringUtils';

async function checkIamInstanceRoles(region: string = 'us-east-1'): Promise<ComplianceReport> {
  const client = new EC2Client({ region });
  const results: ComplianceReport = {
    checks: [],
    metadoc: {
      title: 'Ensure IAM instance roles are used for AWS resource access from instances',
      description: 'AWS access from within AWS instances can be done by either encoding AWS keys into AWS API calls or by assigning the instance to a role which has an appropriate permissions policy for the required access. AWS Access means accessing the APIs of AWS in order to access AWS resources or manage AWS account resources.',
      controls: [{
        id: 'CIS-AWS-Foundations-Benchmark_v3.0.0_1.18',
        document: 'CIS-AWS-Foundations-Benchmark_v3.0.0'
      }]
    }
  };

  try {
    let nextToken: string | undefined;
    let instanceFound = false;

    do {
      const command = new DescribeInstancesCommand({
        NextToken: nextToken,
        Filters: [{
          Name: 'instance-state-name',
          Values: ['running', 'pending']
        }]
      });

      const response = await client.send(command);

      if (!response.Reservations || response.Reservations.length === 0) {
        if (!instanceFound) {
          results.checks = [{
            resourceName: 'No EC2 Instances',
            status: ComplianceStatus.NOTAPPLICABLE,
            message: 'No running EC2 instances found in the region'
          }];
          return results;
        }
        break;
      }

      for (const reservation of response.Reservations) {
        if (!reservation.Instances) continue;

        for (const instance of reservation.Instances) {
          instanceFound = true;
          const instanceId = instance.InstanceId || 'Unknown Instance';

          if (!instance.InstanceId) {
            results.checks.push({
              resourceName: 'Unknown Instance',
              status: ComplianceStatus.ERROR,
              message: 'Instance found without Instance ID'
            });
            continue;
          }

          const hasIamRole = instance.IamInstanceProfile !== undefined;

          results.checks.push({
            resourceName: instanceId,
            resourceArn: instance.IamInstanceProfile?.Arn,
            status: hasIamRole ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
            message: hasIamRole ? undefined : 'EC2 instance does not have an IAM role attached'
          });
        }
      }

      nextToken = response.NextToken;
    } while (nextToken);

  } catch (error) {
    results.checks = [{
      resourceName: 'Region Check',
      status: ComplianceStatus.ERROR,
      message: `Error checking EC2 instances: ${error instanceof Error ? error.message : String(error)}`
    }];
    return results;
  }

  return results;
}

if (require.main === module) {
  const region = process.env.AWS_REGION ?? 'ap-southeast-1';
  const results = await checkIamInstanceRoles(region);
  printSummary(generateSummary(results));
}

export default checkIamInstanceRoles;