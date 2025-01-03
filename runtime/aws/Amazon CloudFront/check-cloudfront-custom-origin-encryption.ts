import { CloudFrontClient, ListDistributionsCommand, GetDistributionCommand } from '@aws-sdk/client-cloudfront';
import { printSummary, generateSummary } from '../../utils/string-utils.js';
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from '../../types.js';

async function checkCloudFrontCustomOriginEncryption(
  region: string = 'us-east-1'
): Promise<ComplianceReport> {
  const client = new CloudFrontClient({ region });
  const results: ComplianceReport = {
    checks: []
  };

  try {
    const listCommand = new ListDistributionsCommand({});
    const response = await client.send(listCommand);

    if (!response.DistributionList?.Items || response.DistributionList.Items.length === 0) {
      results.checks.push({
        resourceName: 'No CloudFront Distributions',
        status: ComplianceStatus.NOTAPPLICABLE,
        message: 'No CloudFront distributions found'
      });
      return results;
    }

    for (const distribution of response.DistributionList.Items) {
      if (!distribution.Id) continue;

      try {
        const getCommand = new GetDistributionCommand({ Id: distribution.Id });
        const distDetails = await client.send(getCommand);
        const config = distDetails.Distribution?.DistributionConfig;

        if (!config) {
          results.checks.push({
            resourceName: distribution.Id,
            status: ComplianceStatus.ERROR,
            message: 'Unable to retrieve distribution configuration'
          });
          continue;
        }

        let isCompliant = true;
        let violationMessage = '';

        // Check each origin for compliance
        for (const origin of config.Origins?.Items || []) {
          if (origin.CustomOriginConfig) {
            // Check for http-only protocol policy
            if (origin.CustomOriginConfig.OriginProtocolPolicy === 'http-only') {
              isCompliant = false;
              violationMessage = 'Distribution uses http-only origin protocol policy';
              break;
            }

            // Check for match-viewer with allow-all viewer protocol policy
            if (
              origin.CustomOriginConfig.OriginProtocolPolicy === 'match-viewer' &&
              config.DefaultCacheBehavior?.ViewerProtocolPolicy === 'allow-all'
            ) {
              isCompliant = false;
              violationMessage =
                'Distribution uses match-viewer origin protocol policy with allow-all viewer protocol policy';
              break;
            }
          }
        }

        results.checks.push({
          resourceName: distribution.Id,
          resourceArn: distribution.ARN,
          status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
          message: isCompliant ? undefined : violationMessage
        });
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
      resourceName: 'CloudFront Check',
      status: ComplianceStatus.ERROR,
      message: `Error checking CloudFront distributions: ${error instanceof Error ? error.message : String(error)}`
    });
  }

  return results;
}

if (import.meta.main) {
  const region = process.env.AWS_REGION;
  const results = await checkCloudFrontCustomOriginEncryption(region);
  printSummary(generateSummary(results));
}

export default {
  title: 'CloudFront distributions should encrypt traffic to custom origins',
  description: 'This control checks if Amazon CloudFront distributions are encrypting traffic to custom origins. This control fails for a CloudFront distribution whose origin protocol policy allows \'http-only\'. This control also fails if the distribution\'s origin protocol policy is \'match-viewer\' while the viewer protocol policy is \'allow-all\'. HTTPS (TLS) can be used to help prevent eavesdropping or manipulation of network traffic. Only encrypted connections over HTTPS (TLS) should be allowed',
  controls: [
    {
      id: 'AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.9',
      document: 'AWS-Foundational-Security-Best-Practices_v1.0.0'
    }
  ],
  severity: 'MEDIUM',
  execute: checkCloudFrontCustomOriginEncryption
} satisfies RuntimeTest;