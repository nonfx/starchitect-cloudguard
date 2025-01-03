import { CloudFrontClient, ListDistributionsCommand } from "@aws-sdk/client-cloudfront";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkCloudFrontSniCompliance(
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

      const viewerCertificate = distribution.ViewerCertificate;
      
      // Skip check if using CloudFront default certificate
      if (viewerCertificate?.CloudFrontDefaultCertificate) {
        results.checks.push({
          resourceName: distribution.Id,
          resourceArn: distribution.ARN,
          status: ComplianceStatus.PASS,
          message: "Using CloudFront default certificate"
        });
        continue;
      }

      // Check if custom certificate is using SNI
      const usesSNI = viewerCertificate?.SSLSupportMethod === "sni-only";

      results.checks.push({
        resourceName: distribution.Id,
        resourceArn: distribution.ARN,
        status: usesSNI ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
        message: usesSNI
          ? undefined
          : "Distribution is not configured to use SNI for HTTPS requests"
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
  }

  return results;
}

if (import.meta.main) {
  const region = process.env.AWS_REGION;
  const results = await checkCloudFrontSniCompliance(region);
  printSummary(generateSummary(results));
}

export default {
  title: "CloudFront distributions should use SNI to serve HTTPS requests",
  description: "This control checks if Amazon CloudFront distributions are using a custom SSL/TLS certificate and are configured to use SNI to serve HTTPS requests. This control fails if a custom SSL/TLS certificate is associated but the SSL/TLS support method is a dedicated IP address. Server Name Indication (SNI) is an extension to the TLS protocol that is supported by browsers and clients released after 2010. If you configure CloudFront to serve HTTPS requests using SNI, CloudFront associates your alternate domain name with an IP address for each edge location. When a viewer submits an HTTPS request for your content, DNS routes the request to the IP address for the correct edge location. The IP address to your domain name is determined during the SSL/TLS handshake negotiation; the IP address isn't dedicated to your distribution",
  controls: [
    {
      id: "AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.8",
      document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
    }
  ],
  severity: "MEDIUM",
  execute: checkCloudFrontSniCompliance
} satisfies RuntimeTest;