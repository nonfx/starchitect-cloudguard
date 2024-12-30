import { RDSClient, DescribeDBInstancesCommand, ListTagsForResourceCommand } from "@aws-sdk/client-rds";
import { IAMClient, GetRolePolicyCommand, ListRolePoliciesCommand, ListAttachedRolePoliciesCommand, GetPolicyVersionCommand } from "@aws-sdk/client-iam";
import { generateSummary, printSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

interface PolicyDocument {
  Version: string;
  Statement: Array<{
    Effect: string;
    Action: string | string[];
    Resource: string | string[];
  }>;
}

async function checkAuroraLeastPrivilegeCompliance(
  region: string = "us-east-1"
): Promise<ComplianceReport> {
  const rdsClient = new RDSClient({ region });
  const iamClient = new IAMClient({ region });
  const results: ComplianceReport = {
    checks: []
  };

  try {
    // Get Aurora DB instances
    const dbInstances = await rdsClient.send(new DescribeDBInstancesCommand({
      Filters: [{
        Name: "engine",
        Values: ["aurora", "aurora-mysql", "aurora-postgresql"]
      }]
    }));

    if (!dbInstances.DBInstances || dbInstances.DBInstances.length === 0) {
      results.checks.push({
        resourceName: "Aurora Instances",
        status: ComplianceStatus.NOTAPPLICABLE,
        message: "No Aurora instances found"
      });
      return results;
    }

    for (const instance of dbInstances.DBInstances) {
      if (!instance.DBInstanceArn || !instance.DBInstanceIdentifier) continue;

      // Check associated IAM roles
      if (instance.AssociatedRoles) {
        for (const role of instance.AssociatedRoles) {
          if (!role.RoleArn) continue;

          try {
            // Check inline policies
            const inlinePolicies = await iamClient.send(new ListRolePoliciesCommand({
              RoleName: role.RoleArn.split("/").pop()
            }));

            for (const policyName of inlinePolicies.PolicyNames || []) {
              const policyDetails = await iamClient.send(new GetRolePolicyCommand({
                RoleName: role.RoleArn.split("/").pop(),
                PolicyName: policyName
              }));

              const hasOverPrivileges = checkPolicyPrivileges(policyDetails.PolicyDocument);
              if (hasOverPrivileges) {
                results.checks.push({
                  resourceName: instance.DBInstanceIdentifier,
                  resourceArn: instance.DBInstanceArn,
                  status: ComplianceStatus.FAIL,
                  message: `Role ${role.RoleArn} has excessive privileges in inline policy ${policyName}`
                });
                continue;
              }
            }

            // Check attached policies
            const attachedPolicies = await iamClient.send(new ListAttachedRolePoliciesCommand({
              RoleName: role.RoleArn.split("/").pop()
            }));

            for (const policy of attachedPolicies.AttachedPolicies || []) {
              if (!policy.PolicyArn) continue;

              const policyVersion = await iamClient.send(new GetPolicyVersionCommand({
                PolicyArn: policy.PolicyArn,
                VersionId: "v1"
              }));

              if (policyVersion.PolicyVersion?.Document) {
                const hasOverPrivileges = checkPolicyPrivileges(policyVersion.PolicyVersion.Document);
                if (hasOverPrivileges) {
                  results.checks.push({
                    resourceName: instance.DBInstanceIdentifier,
                    resourceArn: instance.DBInstanceArn,
                    status: ComplianceStatus.FAIL,
                    message: `Role ${role.RoleArn} has excessive privileges in attached policy ${policy.PolicyName}`
                  });
                  continue;
                }
              }
            }

            results.checks.push({
              resourceName: instance.DBInstanceIdentifier,
              resourceArn: instance.DBInstanceArn,
              status: ComplianceStatus.PASS,
              message: `Role ${role.RoleArn} follows least privilege principle`
            });

          } catch (error) {
            results.checks.push({
              resourceName: instance.DBInstanceIdentifier,
              resourceArn: instance.DBInstanceArn,
              status: ComplianceStatus.ERROR,
              message: `Error checking role ${role.RoleArn}: ${error instanceof Error ? error.message : String(error)}`
            });
          }
        }
      }
    }
  } catch (error) {
    results.checks.push({
      resourceName: "Aurora Check",
      status: ComplianceStatus.ERROR,
      message: `Error checking Aurora instances: ${error instanceof Error ? error.message : String(error)}`
    });
  }

  return results;
}

function checkPolicyPrivileges(policyDocument: string | undefined): boolean {
  if (!policyDocument) return false;

  try {
    const policy: PolicyDocument = typeof policyDocument === 'string' 
      ? JSON.parse(decodeURIComponent(policyDocument))
      : policyDocument;

    return policy.Statement.some(stmt => {
      const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
      const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource];

      return stmt.Effect === "Allow" && 
             (actions.includes("*") || actions.includes("rds:*")) &&
             resources.includes("*");
    });
  } catch {
    return false;
  }
}

if (require.main === module) {
  const region = process.env.AWS_REGION;
  const results = await checkAuroraLeastPrivilegeCompliance(region);
  printSummary(generateSummary(results));
}

export default {
  title: "Ensure Least Privilege Access",
  description: "Use the principle of least privilege when granting access to your Amazon Aurora resources. This principle of least privilege (POLP) is a computer security concept where users are given the minimum access levels necessary to complete their job functions. In Amazon Aurora, this can be implemented at various levels, including AWS IAM for managing AWS resources and within the database for managing database users and roles.",
  controls: [
    {
      id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.2",
      document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
    }
  ],
  severity: "HIGH",
  execute: checkAuroraLeastPrivilegeCompliance
} satisfies RuntimeTest;