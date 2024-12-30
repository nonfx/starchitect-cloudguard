import { RDSClient, DescribeDBInstancesCommand, DescribeDBClustersCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkDatabaseSecurityConfiguration(
  region: string = "us-east-1"
): Promise<ComplianceReport> {
  const client = new RDSClient({ region });
  const results: ComplianceReport = {
    checks: []
  };

  try {
    // Check DB Instances
    const instancesResponse = await client.send(new DescribeDBInstancesCommand({}));
    const instances = instancesResponse.DBInstances || [];

    // Check DB Clusters
    const clustersResponse = await client.send(new DescribeDBClustersCommand({}));
    const clusters = clustersResponse.DBClusters || [];

    if (instances.length === 0 && clusters.length === 0) {
      results.checks.push({
        resourceName: "No Databases",
        status: ComplianceStatus.NOTAPPLICABLE,
        message: "No RDS instances or clusters found in the region"
      });
      return results;
    }

    // Check instances
    for (const instance of instances) {
      if (!instance.DBInstanceIdentifier || !instance.DBInstanceArn) continue;

      const securityIssues = [];

      // Check encryption
      if (!instance.StorageEncrypted) {
        securityIssues.push("Storage is not encrypted");
      }

      // Check public accessibility
      if (instance.PubliclyAccessible) {
        securityIssues.push("Instance is publicly accessible");
      }

      // Check backup retention
      if (!instance.BackupRetentionPeriod || instance.BackupRetentionPeriod < 7) {
        securityIssues.push("Backup retention period is less than 7 days");
      }

      // Check monitoring
      if (!instance.EnhancedMonitoringResourceArn) {
        securityIssues.push("Enhanced monitoring is not enabled");
      }

      results.checks.push({
        resourceName: instance.DBInstanceIdentifier,
        resourceArn: instance.DBInstanceArn,
        status: securityIssues.length === 0 ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
        message: securityIssues.length > 0 ? securityIssues.join("; ") : undefined
      });
    }

    // Check clusters
    for (const cluster of clusters) {
      if (!cluster.DBClusterIdentifier || !cluster.DBClusterArn) continue;

      const securityIssues = [];

      // Check encryption
      if (!cluster.StorageEncrypted) {
        securityIssues.push("Storage is not encrypted");
      }

      // Check backup retention
      if (!cluster.BackupRetentionPeriod || cluster.BackupRetentionPeriod < 7) {
        securityIssues.push("Backup retention period is less than 7 days");
      }

      // Check deletion protection
      if (!cluster.DeletionProtection) {
        securityIssues.push("Deletion protection is not enabled");
      }

      results.checks.push({
        resourceName: cluster.DBClusterIdentifier,
        resourceArn: cluster.DBClusterArn,
        status: securityIssues.length === 0 ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
        message: securityIssues.length > 0 ? securityIssues.join("; ") : undefined
      });
    }
  } catch (error) {
    results.checks.push({
      resourceName: "Database Security Check",
      status: ComplianceStatus.ERROR,
      message: `Error checking database security configuration: ${error instanceof Error ? error.message : String(error)}`
    });
  }

  return results;
}

if (require.main === module) {
  const region = process.env.AWS_REGION;
  const results = await checkDatabaseSecurityConfiguration(region);
  printSummary(generateSummary(results));
}

export default {
  title: "Ensure to Regularly Review Security Configuration",
  description: "This helps by reviewing the database factors from database engine, review instance details, security networks, encryption settings, audit logging, and authentication. By updating or removing a few things from these lists it helps tighten security and ensures that the users do not have excessive permissions",
  controls: [
    {
      id: "AWS-Security-Best-Practices_v1.0.0_DB.1",
      document: "AWS-Security-Best-Practices_v1.0.0"
    }
  ],
  severity: "HIGH",
  execute: checkDatabaseSecurityConfiguration
} satisfies RuntimeTest;