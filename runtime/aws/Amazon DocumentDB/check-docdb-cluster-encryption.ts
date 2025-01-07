import { DocDBClient, DescribeDBClustersCommand } from '@aws-sdk/client-docdb';
import { printSummary, generateSummary } from '../../utils/string-utils.js';
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from '../../types.js';

async function checkDocDBClusterEncryption(region: string = 'us-east-1'): Promise<ComplianceReport> {
  const client = new DocDBClient({ region });
  const results: ComplianceReport = {
    checks: []
  };

  try {
    // Get all DocumentDB clusters
    const response = await client.send(new DescribeDBClustersCommand({}));

    if (!response.DBClusters || response.DBClusters.length === 0) {
      results.checks = [{
        resourceName: 'No DocumentDB Clusters',
        status: ComplianceStatus.NOTAPPLICABLE,
        message: 'No DocumentDB clusters found in the region'
      }];
      return results;
    }

    // Check encryption status for each cluster
    for (const cluster of response.DBClusters) {
      if (!cluster.DBClusterIdentifier) {
        results.checks.push({
          resourceName: 'Unknown Cluster',
          status: ComplianceStatus.ERROR,
          message: 'Cluster found without identifier'
        });
        continue;
      }

      results.checks.push({
        resourceName: cluster.DBClusterIdentifier,
        resourceArn: cluster.DBClusterArn,
        status: cluster.StorageEncrypted ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
        message: cluster.StorageEncrypted
          ? undefined
          : 'DocumentDB cluster is not encrypted at rest'
      });
    }
  } catch (error) {
    results.checks = [{
      resourceName: 'Region Check',
      status: ComplianceStatus.ERROR,
      message: `Error checking DocumentDB clusters: ${error instanceof Error ? error.message : String(error)}`
    }];
  }

  return results;
}

if (import.meta.main) {
  const region = process.env.AWS_REGION;
  const results = await checkDocDBClusterEncryption(region);
  printSummary(generateSummary(results));
}

export default {
  title: 'Amazon DocumentDB clusters should be encrypted at rest',
  description: 'Amazon DocumentDB clusters must implement encryption at rest using AES-256 for enhanced data security and compliance.',
  controls: [{
    id: 'AWS-Foundational-Security-Best-Practices_v1.0.0_DocumentDB.1',
    document: 'AWS-Foundational-Security-Best-Practices_v1.0.0'
  }],
  severity: 'MEDIUM',
  execute: checkDocDBClusterEncryption,
  serviceName: 'Amazon DocumentDB',
  shortServiceName: 'docdb'
} satisfies RuntimeTest;