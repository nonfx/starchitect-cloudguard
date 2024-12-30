import { IAMClient, ListAccessKeysCommand, GetAccessKeyLastUsedCommand } from "@aws-sdk/client-iam";
import { generateSummary, printSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

const MAX_KEY_AGE_DAYS = 90;

async function checkAccessKeyRotation(region: string = "us-east-1"): Promise<ComplianceReport> {
  const client = new IAMClient({ region });
  const results: ComplianceReport = {
    checks: []
  };

  try {
    // Get all access keys
    const command = new ListAccessKeysCommand({});
    const response = await client.send(command);

    if (!response.AccessKeyMetadata || response.AccessKeyMetadata.length === 0) {
      results.checks = [{
        resourceName: "No Access Keys",
        status: ComplianceStatus.NOTAPPLICABLE,
        message: "No access keys found"
      }];
      return results;
    }

    for (const key of response.AccessKeyMetadata) {
      if (!key.AccessKeyId || !key.CreateDate) {
        results.checks.push({
          resourceName: key.AccessKeyId || "Unknown Key",
          status: ComplianceStatus.ERROR,
          message: "Access key missing required metadata"
        });
        continue;
      }

      try {
        // Get last used information
        const lastUsedCommand = new GetAccessKeyLastUsedCommand({
          AccessKeyId: key.AccessKeyId
        });
        const lastUsedResponse = await client.send(lastUsedCommand);

        const keyAge = Math.floor(
          (new Date().getTime() - key.CreateDate.getTime()) / (1000 * 60 * 60 * 24)
        );

        const isCompliant = keyAge <= MAX_KEY_AGE_DAYS;

        results.checks.push({
          resourceName: key.AccessKeyId,
          resourceArn: `arn:aws:iam::${lastUsedResponse.UserName}:access-key/${key.AccessKeyId}`,
          status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
          message: isCompliant
            ? undefined
            : `Access key is ${keyAge} days old (maximum allowed age is ${MAX_KEY_AGE_DAYS} days)`
        });
      } catch (error) {
        results.checks.push({
          resourceName: key.AccessKeyId,
          status: ComplianceStatus.ERROR,
          message: `Error checking key last usage: ${error instanceof Error ? error.message : String(error)}`
        });
      }
    }
  } catch (error) {
    results.checks = [{
      resourceName: "Access Keys Check",
      status: ComplianceStatus.ERROR,
      message: `Error checking access keys: ${error instanceof Error ? error.message : String(error)}`
    }];
    return results;
  }

  return results;
}

if (require.main === module) {
  const region = process.env.AWS_REGION;
  const results = await checkAccessKeyRotation(region);
  printSummary(generateSummary(results));
}

export default {
  title: "Ensure access keys are rotated every 90 days or less",
  description: "Access keys consist of an access key ID and secret access key, which are used to sign programmatic requests that you make to AWS. AWS users need their own access keys to make programmatic calls to AWS from the AWS Command Line Interface (AWS CLI), Tools for Windows PowerShell, the AWS SDKs, or direct HTTP calls using the APIs for individual AWS services. It is recommended that all access keys be regularly rotated.",
  controls: [{
    id: "CIS-AWS-Foundations-Benchmark_v3.0.0_1.4",
    document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
  }],
  severity: "MEDIUM",
  execute: checkAccessKeyRotation
} satisfies RuntimeTest;