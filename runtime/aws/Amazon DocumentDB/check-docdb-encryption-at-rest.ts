import { DocDBClient, DescribeDBClustersCommand } from '@aws-sdk/client-docdb';
import { printSummary, generateSummary } from '../../utils/string-utils.js';
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from '../../types.js';

async function checkDocDBEncryptionAtRest(region: string = 'us-east-1'): Promise<ComplianceReport> {
  const client = new DocDBClient({ region });
  const results: ComplianceReport = {
    checks: []
  };

  try {
    const command = new DescribeDBClustersCommand({});
    const response = await client.send(command);

    if (!response.DBClusters || response.DBClusters.length === 0) {
      results.checks = [{
        resourceName: 'No DocumentDB Clusters',
        status: ComplianceStatus.NOTAPPLICABLE,
        message: 'No DocumentDB clusters found in the region'
      }];
      return results;
    }

    for (const cluster of response.DBClusters) {
      if (!cluster.DBClusterIdentifier || !cluster.DBClusterArn) {
        results.checks.push({
          resourceName: 'Unknown Cluster',
          status: ComplianceStatus.ERROR,
          message: 'Cluster found without identifier or ARN'
        });
        continue;
      }

      results.checks.push({
        resourceName: cluster.DBClusterIdentifier,
        resourceArn: cluster.DBClusterArn,
        status: cluster.StorageEncrypted ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
        message: cluster.StorageEncrypted ? undefined : 'DocumentDB cluster is not encrypted at rest'
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
  const results = await checkDocDBEncryptionAtRest(region);
  printSummary(generateSummary(results));
}

export default {
  title: 'Ensure Encryption at Rest is Enabled',
  description: 'This helps ensure that the data is kept secure and protected when at rest. The user must choose from two key options which then determine when the data is encrypted at rest.',
  controls: [{
    id: 'CIS-AWS-Database-Services-Benchmark_v1.0.0_7.3',
    document: 'CIS-AWS-Database-Services-Benchmark_v1.0.0'
  }],
  severity: 'HIGH',
  execute: checkDocDBEncryptionAtRest,
  serviceName: 'Amazon DocumentDB',
  shortServiceName: 'docdb'
} satisfies RuntimeTest;