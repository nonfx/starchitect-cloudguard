import { CloudFrontClient, ListDistributionsCommand, GetDistributionCommand } from '@aws-sdk/client-cloudfront';
import { printSummary, generateSummary } from '../../utils/string-utils.js';
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from '../../types.js';

async function checkCloudFrontOriginFailover(region: string = 'us-east-1'): Promise<ComplianceReport> {
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
      if (!distribution.Id) {
        results.checks.push({
          resourceName: 'Unknown Distribution',
          status: ComplianceStatus.ERROR,
          message: 'Distribution found without ID'
        });
        continue;
      }

      try {
        const getCommand = new GetDistributionCommand({
          Id: distribution.Id
        });
        const distDetails = await client.send(getCommand);

        if (!distDetails.Distribution?.DistributionConfig) {
          results.checks.push({
            resourceName: distribution.Id,
            status: ComplianceStatus.ERROR,
            message: 'Unable to get distribution configuration'
          });
          continue;
        }

        const config = distDetails.Distribution.DistributionConfig;
        const hasOriginGroups = config.OriginGroups?.Items && config.OriginGroups.Items.length > 0;
        const hasMultipleOrigins = hasOriginGroups && 
          config.OriginGroups.Items.some(group => group.Members?.Items && group.Members.Items.length >= 2);

        results.checks.push({
          resourceName: distribution.Id,
          resourceArn: distribution.ARN,
          status: hasMultipleOrigins ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
          message: hasMultipleOrigins ? undefined : 'Distribution does not have origin failover configured with at least two origins'
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
  const results = await checkCloudFrontOriginFailover(region);
  printSummary(generateSummary(results));
}

export default {
  title: 'CloudFront distributions should have origin failover configured',
  description: 'This control checks whether an Amazon CloudFront distribution is configured with an origin group that has two or more origins. CloudFront origin failover can increase availability. Origin failover automatically redirects traffic to a secondary origin if the primary origin is unavailable or if it returns specific HTTP response status codes.',
  controls: [{
    id: 'AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.4',
    document: 'AWS-Foundational-Security-Best-Practices_v1.0.0'
  }],
  severity: 'MEDIUM',
  execute: checkCloudFrontOriginFailover
} satisfies RuntimeTest;