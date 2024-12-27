import {
	RDSClient,
	DescribeDBClustersCommand,
	DescribeDBClusterParameterGroupsCommand,
	DescribeDBClusterParametersCommand
} from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

async function checkAuroraEncryptionInTransit(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all Aurora clusters
		const clusters = await client.send(new DescribeDBClustersCommand({}));

		if (!clusters.DBClusters || clusters.DBClusters.length === 0) {
			results.checks = [
				{
					resourceName: "No Aurora Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Aurora clusters found in the region"
				}
			];
			return results;
		}

		for (const cluster of clusters.DBClusters) {
			if (!cluster.DBClusterIdentifier || !cluster.DBClusterParameterGroup) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without identifier or parameter group"
				});
				continue;
			}

			try {
				// Get parameter group details
				const paramGroup = await client.send(
					new DescribeDBClusterParameterGroupsCommand({
						DBClusterParameterGroupName: cluster.DBClusterParameterGroup
					})
				);

				if (!paramGroup.DBClusterParameterGroups?.[0]?.DBParameterGroupFamily) {
					results.checks.push({
						resourceName: cluster.DBClusterIdentifier,
						status: ComplianceStatus.ERROR,
						message: "Unable to determine parameter group family"
					});
					continue;
				}

				const isPostgres =
					paramGroup.DBClusterParameterGroups[0].DBParameterGroupFamily.startsWith(
						"aurora-postgresql"
					);
				const isMysql =
					paramGroup.DBClusterParameterGroups[0].DBParameterGroupFamily.startsWith("aurora-mysql");

				// Get all parameters with pagination
				const allParameters = [];
				let marker: string | undefined;

				do {
					const parametersResponse = await client.send(
						new DescribeDBClusterParametersCommand({
							DBClusterParameterGroupName: cluster.DBClusterParameterGroup,
							Marker: marker
						})
					);

					if (parametersResponse.Parameters) {
						allParameters.push(...parametersResponse.Parameters);
					}

					marker = parametersResponse.Marker;
				} while (marker);

				let sslEnforced = false;

				if (isPostgres) {
					sslEnforced = allParameters.some(
						param => param.ParameterName === "rds.force_ssl" && param.ParameterValue === "1"
					);
				} else if (isMysql) {
					sslEnforced = allParameters.some(
						param =>
							param.ParameterName === "require_secure_transport" && param.ParameterValue === "1"
					);
				}

				results.checks.push({
					resourceName: cluster.DBClusterIdentifier,
					resourceArn: cluster.DBClusterArn,
					status: sslEnforced ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: sslEnforced
						? undefined
						: "SSL connections are not enforced for this Aurora cluster"
				});
			} catch (error) {
				results.checks.push({
					resourceName: cluster.DBClusterIdentifier,
					resourceArn: cluster.DBClusterArn,
					status: ComplianceStatus.ERROR,
					message: `Error checking cluster parameters: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Aurora Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Aurora clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION;
	const results = await checkAuroraEncryptionInTransit(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Data in Transit is Encrypted",
	description:
		"Use SSL (Secure Sockets Layer) to secure data in transit. Aurora supports SSL-encrypted connections between your application and your DB instance",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_2.4",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkAuroraEncryptionInTransit
} satisfies RuntimeTest;
