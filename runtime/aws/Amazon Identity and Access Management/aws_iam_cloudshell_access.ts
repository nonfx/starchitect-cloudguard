import { IAMClient, ListAttachedUserPoliciesCommand, ListAttachedGroupPoliciesCommand, ListAttachedRolePoliciesCommand, ListUsersCommand, ListGroupsCommand, ListRolesCommand } from '@aws-sdk/client-iam';

import { printSummary, generateSummary } from '~codegen/utils/stringUtils';
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

const CLOUDSHELL_FULL_ACCESS_ARN = 'arn:aws:iam::aws:policy/AWSCloudShellFullAccess';

async function checkCloudShellAccess(region: string = 'us-east-1'): Promise<ComplianceReport> {
  const client = new IAMClient({ region });
  const results: ComplianceReport = {
    checks: []
  };

  try {
    // Check Users
    const users = await client.send(new ListUsersCommand({}));
    if (users.Users) {
      for (const user of users.Users) {
        if (!user.UserName) continue;

        const userPolicies = await client.send(new ListAttachedUserPoliciesCommand({
          UserName: user.UserName
        }));

        const hasCloudShellAccess = userPolicies.AttachedPolicies?.some(
          policy => policy.PolicyArn === CLOUDSHELL_FULL_ACCESS_ARN
        );

        if (hasCloudShellAccess) {
          results.checks.push({
            resourceName: user.UserName,
            resourceArn: user.Arn,
            status: ComplianceStatus.FAIL,
            message: 'User has AWSCloudShellFullAccess policy attached directly'
          });
        }
      }
    }

    // Check Groups
    const groups = await client.send(new ListGroupsCommand({}));
    if (groups.Groups) {
      for (const group of groups.Groups) {
        if (!group.GroupName) continue;

        const groupPolicies = await client.send(new ListAttachedGroupPoliciesCommand({
          GroupName: group.GroupName
        }));

        const hasCloudShellAccess = groupPolicies.AttachedPolicies?.some(
          policy => policy.PolicyArn === CLOUDSHELL_FULL_ACCESS_ARN
        );

        if (hasCloudShellAccess) {
          results.checks.push({
            resourceName: group.GroupName,
            resourceArn: group.Arn,
            status: ComplianceStatus.FAIL,
            message: 'Group has AWSCloudShellFullAccess policy attached'
          });
        }
      }
    }

    // Check Roles
    const roles = await client.send(new ListRolesCommand({}));
    if (roles.Roles) {
      for (const role of roles.Roles) {
        if (!role.RoleName) continue;

        const rolePolicies = await client.send(new ListAttachedRolePoliciesCommand({
          RoleName: role.RoleName
        }));

        const hasCloudShellAccess = rolePolicies.AttachedPolicies?.some(
          policy => policy.PolicyArn === CLOUDSHELL_FULL_ACCESS_ARN
        );

        if (hasCloudShellAccess) {
          results.checks.push({
            resourceName: role.RoleName,
            resourceArn: role.Arn,
            status: ComplianceStatus.FAIL,
            message: 'Role has AWSCloudShellFullAccess policy attached'
          });
        }
      }
    }

    // If no failures found, add a PASS check
    if (results.checks.length === 0) {
      results.checks.push({
        resourceName: 'AWS Account',
        status: ComplianceStatus.PASS,
        message: 'No entities with AWSCloudShellFullAccess policy found'
      });
    }

  } catch (error) {
    results.checks.push({
      resourceName: 'IAM Check',
      status: ComplianceStatus.ERROR,
      message: `Error checking CloudShell access: ${error instanceof Error ? error.message : String(error)}`
    });
  }

  return results;
}

if (require.main === module) {
  const region = process.env.AWS_REGION ?? 'ap-southeast-1';
  const results = await checkCloudShellAccess(region);
  printSummary(generateSummary(results));
}

export default {
  title: 'Ensure access to AWSCloudShellFullAccess is restricted',
  description: 'AWS CloudShell is a convenient way of running CLI commands against AWS services; a managed IAM policy (\'AWSCloudShellFullAccess\') provides full access to CloudShell, which allows file upload and download capability between a user\'s local system and the CloudShell environment. Within the CloudShell environment a user has sudo permissions, and can access the internet. So it is feasible to install file transfer software (for example) and move data from CloudShell to external internet servers.',
  controls: [{
    id: 'CIS-AWS-Foundations-Benchmark_v3.0.0_1.22',
    document: 'CIS-AWS-Foundations-Benchmark_v3.0.0'
  }],
  severity: 'MEDIUM',
  execute: checkCloudShellAccess
} satisfies RuntimeTest;