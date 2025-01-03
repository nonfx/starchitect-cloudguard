import { CloudFrontClient, ListDistributionsCommand } from '@aws-sdk/client-cloudfront';
import { printSummary, generateSummary } from '../../utils/string-utils.js';
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from '../../types.js';

async function checkCloudFrontWafCompliance(
  region: string = 'us-east-1'
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
          resourceName: 'No CloudFront Distributions',
          status: ComplianceStatus.NOTAPPLICABLE,
          message: 'No CloudFront distributions found'
        }
      ];
      return results;
    }

    for (const distribution of response.DistributionList.Items) {
      if (!distribution.Id || !distribution.ARN) {
        results.checks.push({
          resourceName: 'Unknown Distribution',
          status: ComplianceStatus.ERROR,
          message: 'Distribution found without ID or ARN'
        });
        continue;
      }

      const hasWaf = distribution.WebACLId !== undefined && distribution.WebACLId !== '';

      results.checks.push({
        resourceName: distribution.Id,
        resourceArn: distribution.ARN,
        status: hasWaf ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
        message: hasWaf ? undefined : 'CloudFront distribution does not have WAF enabled'
      });
    }
  } catch (error) {
    results.checks = [
      {
        resourceName: 'CloudFront Check',
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
  const results = await checkCloudFrontWafCompliance(region);
  printSummary(generateSummary(results));
}

export default {
  title: 'CloudFront distributions should have WAF enabled',
  description: 'This control checks whether CloudFront distributions are associated with either AWS WAF Classic or AWS WAF web ACLs. The control fails if the distribution is not associated with a web ACL. AWS WAF is a web application firewall that helps protect web applications and APIs from attacks. It allows you to configure a set of rules, called a web access control list (web ACL), that allow, block, or count web requests based on customizable web security rules and conditions that you define. Ensure your CloudFront distribution is associated with an AWS WAF web ACL to help protect it from malicious attacks',
  controls: [
    {
      id: 'AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.6',
      document: 'AWS-Foundational-Security-Best-Practices_v1.0.0'
    }
  ],
  severity: 'MEDIUM',
  execute: checkCloudFrontWafCompliance,
  serviceName: 'Amazon CloudFront',
  shortServiceName: 'cloudfront'
} satisfies RuntimeTest;