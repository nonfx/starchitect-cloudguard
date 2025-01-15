import { AccountClient, GetAlternateContactCommand } from "@aws-sdk/client-account";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkSecurityContactCompliance(
  region: string = "us-east-1"
): Promise<ComplianceReport> {
  const client = new AccountClient({ region });
  const results: ComplianceReport = {
    checks: []
  };

  try {
    const command = new GetAlternateContactCommand({
      AlternateContactType: "SECURITY"
    });

    try {
      await client.send(command);
      results.checks.push({
        resourceName: "Account Security Contact",
        status: ComplianceStatus.PASS,
        message: undefined
      });
    } catch (error: any) {
      if (error.name === "ResourceNotFoundException") {
        results.checks.push({
          resourceName: "Account Security Contact",
          status: ComplianceStatus.FAIL,
          message: "No security contact information is configured for the AWS account"
        });
      } else {
        throw error;
      }
    }
  } catch (error) {
    results.checks.push({
      resourceName: "Account Security Contact",
      status: ComplianceStatus.ERROR,
      message: `Error checking security contact: ${error instanceof Error ? error.message : String(error)}`
    });
  }

  return results;
}

if (import.meta.main) {
  const region = process.env.AWS_REGION;
  const results = await checkSecurityContactCompliance(region);
  printSummary(generateSummary(results));
}

export default {
  title: "Security contact information should be provided for an AWS account",
  description: "This control checks if an Amazon Web Services (AWS) account has security contact information. The control fails if security contact information is not provided for the account. Alternate security contacts allow AWS to contact another person about issues with your account in case you're unavailable. Notifications can be from AWS Support, or other AWS service teams about security-related topics associated with your AWS account usage.",
  controls: [
    {
      id: "AWS-Foundational-Security-Best-Practices_v1.0.0_Account.1",
      document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
    }
  ],
  severity: "MEDIUM",
  execute: checkSecurityContactCompliance,
  serviceName: "AWS Account",
  shortServiceName: "account"
} satisfies RuntimeTest;