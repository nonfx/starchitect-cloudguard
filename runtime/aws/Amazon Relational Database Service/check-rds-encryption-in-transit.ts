import {
	RDSClient,
	DescribeDBClustersCommand,
	DescribeDBClusterParametersCommand
} from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkRdsEncryptionInTransit(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all RDS clusters
		const command = new DescribeDBClustersCommand({});
		const response = await client.send(command);

		if (!response.DBClusters || response.DBClusters.length === 0) {
			results.checks = [
				{
					resourceName: "No RDS Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No RDS clusters found in the region"
				}
			];
			return results;
		}

		// Check each cluster for SSL/TLS encryption
		for (const cluster of response.DBClusters) {
			if (!cluster.DBClusterIdentifier) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "RDS cluster found without identifier"
				});
				continue;
			}

			// Get cluster parameter group settings
			if (!cluster.DBClusterParameterGroup) {
				results.checks.push({
					resourceName: cluster.DBClusterIdentifier,
					resourceArn: cluster.DBClusterArn,
					status: ComplianceStatus.ERROR,
					message: "No parameter group found for cluster"
				});
				continue;
			}

			try {
				// Fetch all parameters with pagination
				let allParameters: any[] = [];
				let marker: string | undefined;

				do {
					const paramsResponse = await client.send(
						new DescribeDBClusterParametersCommand({
							DBClusterParameterGroupName: cluster.DBClusterParameterGroup,
							Marker: marker
						})
					);

					if (paramsResponse.Parameters) {
						allParameters = allParameters.concat(paramsResponse.Parameters);
					}

					marker = paramsResponse.Marker;
				} while (marker);

				// Check SSL requirement based on engine type
				const sslParam = allParameters.find(p => {
					if (cluster.Engine?.includes("mysql")) {
						return p.ParameterName === "require_secure_transport";
					}
					if (cluster.Engine?.includes("postgres")) {
						return p.ParameterName === "rds.force_ssl";
					}
					return false;
				});

				const requiresSSL =
					sslParam?.ParameterValue === "1" || sslParam?.ParameterValue?.toLowerCase() === "on";

				results.checks.push({
					resourceName: cluster.DBClusterIdentifier,
					resourceArn: cluster.DBClusterArn,
					status: requiresSSL ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: requiresSSL
						? undefined
						: `RDS cluster does not require SSL/TLS connections (${sslParam?.ParameterName} = ${sslParam?.ParameterValue || "not set"})`
				});
			} catch (paramError) {
				results.checks.push({
					resourceName: cluster.DBClusterIdentifier,
					resourceArn: cluster.DBClusterArn,
					status: ComplianceStatus.ERROR,
					message: `Error checking parameter group: ${paramError instanceof Error ? paramError.message : String(paramError)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "RDS Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking RDS clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkRdsEncryptionInTransit(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Enable Encryption in Transit",
	description:
		"Amazon RDS clusters should be configured to require SSL/TLS connections to ensure data is encrypted in transit. For MySQL clusters, this is controlled by the 'require_secure_transport' parameter, and for PostgreSQL clusters by the 'rds.force_ssl' parameter. While SSL/TLS is enabled by default, requiring SSL connections provides an additional layer of security by preventing unencrypted connections.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_3.6",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsEncryptionInTransit
} satisfies RuntimeTest;
