import { CloudFrontClient, ListDistributionsCommand, GetDistributionCommand } from "@aws-sdk/client-cloudfront";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkCloudFrontSslProtocols(region: string = "us-east-1"): Promise<ComplianceReport> {
  const client = new CloudFrontClient({ region });
  const results: ComplianceReport = {
    checks: []
  };

  try {
    const listCommand = new ListDistributionsCommand({});
    const response = await client.send(listCommand);

    if (!response.DistributionList?.Items || response.DistributionList.Items.length === 0) {
      results.checks.push({
        resourceName: "No CloudFront Distributions",
        status: ComplianceStatus.NOTAPPLICABLE,
        message: "No CloudFront distributions found"
      });
      return results;
    }

    for (const distribution of response.DistributionList.Items) {
      if (!distribution.Id) {
        results.checks.push({
          resourceName: "Unknown Distribution",
          status: ComplianceStatus.ERROR,
          message: "Distribution found without ID"
        });
        continue;
      }

      try {
        const getCommand = new GetDistributionCommand({ Id: distribution.Id });
        const distConfig = await client.send(getCommand);

        if (!distConfig.Distribution?.DistributionConfig?.Origins?.Items) {
          results.checks.push({
            resourceName: distribution.Id,
            status: ComplianceStatus.ERROR,
            message: "Unable to retrieve distribution configuration"
          });
          continue;
        }

        let hasDeprecatedProtocol = false;
        let hasCustomOrigin = false;

        for (const origin of distConfig.Distribution.DistributionConfig.Origins.Items) {
          if (origin.CustomOriginConfig) {
            hasCustomOrigin = true;
            const protocols = origin.CustomOriginConfig.OriginSslProtocols?.Items || [];
            if (protocols.includes("SSLv3")) {
              hasDeprecatedProtocol = true;
              break;
            }
          }
        }

        if (hasCustomOrigin) {
          results.checks.push({
            resourceName: distribution.Id,
            resourceArn: distribution.ARN,
            status: hasDeprecatedProtocol ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
            message: hasDeprecatedProtocol
              ? "Distribution uses deprecated SSLv3 protocol for custom origins"
              : undefined
          });
        } else {
          results.checks.push({
            resourceName: distribution.Id,
            resourceArn: distribution.ARN,
            status: ComplianceStatus.NOTAPPLICABLE,
            message: "Distribution does not have custom origins configured"
          });
        }
      } catch (error) {
        results.checks.push({
          resourceName: distribution.Id,
          status: ComplianceStatus.ERROR,
          message: `Error checking distribution: ${error instanceof Error ? error.message : String(error)}`
        });
      }
    }
  } catch (error) {
    results.checks.push({
      resourceName: "CloudFront Check",
      status: ComplianceStatus.ERROR,
      message: `Error checking CloudFront distributions: ${error instanceof Error ? error.message : String(error)}`
    });
  }

  return results;
}

if (import.meta.main) {
  const region = process.env.AWS_REGION;
  const results = await checkCloudFrontSslProtocols(region);
  printSummary(generateSummary(results));
}

export default {
  title: "CloudFront distributions should not use deprecated SSL protocols between edge locations and custom origins",
  description: "This control checks if Amazon CloudFront distributions are using deprecated SSL protocols for HTTPS communication between CloudFront edge locations and your custom origins. This control fails if a CloudFront distribution has a CustomOriginConfig where OriginSslProtocols includes SSLv3. In 2015, the Internet Engineering Task Force (IETF) officially announced that SSL 3.0 should be deprecated due to the protocol being insufficiently secure. It is recommended that you use TLSv1.2 or later for HTTPS communication to your custom origins",
  controls: [
    {
      id: "AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.10",
      document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
    }
  ],
  severity: "HIGH",
  execute: checkCloudFrontSslProtocols
} satisfies RuntimeTest;