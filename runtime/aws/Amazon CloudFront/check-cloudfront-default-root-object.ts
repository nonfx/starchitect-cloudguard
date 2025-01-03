import { CloudFrontClient, ListDistributionsCommand } from "@aws-sdk/client-cloudfront";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkCloudFrontDefaultRootObject(
  region: string = "us-east-1"
): Promise<ComplianceReport> {
  const client = new CloudFrontClient({ region });
  const results: ComplianceReport = {
    checks: []
  };

  try {
    const command = new ListDistributionsCommand({});
    const response = await client.send(command);

    if (!response.DistributionList?.Items || response.DistributionList.Items.length === 0) {
      results.checks = [
        {
          resourceName: "No CloudFront Distributions",
          status: ComplianceStatus.NOTAPPLICABLE,
          message: "No CloudFront distributions found"
        }
      ];
      return results;
    }

    for (const distribution of response.DistributionList.Items) {
      if (!distribution.Id || !distribution.ARN) {
        results.checks.push({
          resourceName: "Unknown Distribution",
          status: ComplianceStatus.ERROR,
          message: "Distribution found without ID or ARN"
        });
        continue;
      }

      const hasDefaultRootObject = distribution.DefaultRootObject && 
                                  distribution.DefaultRootObject.trim() !== "";

      results.checks.push({
        resourceName: distribution.Id,
        resourceArn: distribution.ARN,
        status: hasDefaultRootObject ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
        message: hasDefaultRootObject ? 
          undefined : 
          "CloudFront distribution does not have a default root object configured"
      });
    }
  } catch (error) {
    results.checks = [
      {
        resourceName: "CloudFront Check",
        status: ComplianceStatus.ERROR,
        message: `Error checking CloudFront distributions: ${error instanceof Error ? error.message : String(error)}`
      }
    ];
    return results;
  }

  return results;
}

if (import.meta.main) {
  const region = process.env.AWS_REGION;
  const results = await checkCloudFrontDefaultRootObject(region);
  printSummary(generateSummary(results));
}

export default {
  title: "CloudFront distributions should have a default root object configured",
  description: "This control checks whether an Amazon CloudFront distribution is configured to return a specific object that is the default root object. The control fails if the CloudFront distribution does not have a default root object configured. A user might sometimes request the distribution's root URL instead of an object in the distribution. When this happens, specifying a default root object can help you to avoid exposing the contents of your web distribution.",
  controls: [
    {
      id: "AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.1",
      document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
    }
  ],
  severity: "MEDIUM",
  execute: checkCloudFrontDefaultRootObject,
  serviceName: "Amazon CloudFront",
  shortServiceName: "cloudfront"
} satisfies RuntimeTest;