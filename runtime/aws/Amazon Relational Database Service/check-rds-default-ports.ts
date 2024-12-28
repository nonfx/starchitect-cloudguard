import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Default ports for different database engines
const DEFAULT_PORTS: { [key: string]: number } = {
	mysql: 3306,
	"aurora-mysql": 3306,
	postgres: 5432,
	"aurora-postgresql": 5432,
	"oracle-ee": 1521,
	"oracle-se2": 1521,
	"oracle-se1": 1521,
	"oracle-se": 1521,
	"sqlserver-ee": 1433,
	"sqlserver-se": 1433,
	"sqlserver-ex": 1433,
	"sqlserver-web": 1433,
	mariadb: 3306,
	"aurora-mariadb": 3306
};

async function checkRdsDefaultPorts(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let marker: string | undefined;
		let instanceFound = false;

		do {
			const command = new DescribeDBInstancesCommand({
				Marker: marker
			});

			const response = await client.send(command);

			if (!response.DBInstances || response.DBInstances.length === 0) {
				if (!instanceFound) {
					results.checks = [
						{
							resourceName: "No RDS Instances",
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "No RDS instances found in the region"
						}
					];
				}
				break;
			}

			for (const instance of response.DBInstances) {
				instanceFound = true;

				if (!instance.DBInstanceIdentifier || !instance.Engine || !instance.Endpoint?.Port) {
					results.checks.push({
						resourceName: instance.DBInstanceIdentifier || "Unknown Instance",
						resourceArn: instance.DBInstanceArn,
						status: ComplianceStatus.ERROR,
						message: "Instance missing required information (identifier, engine, or port)"
					});
					continue;
				}

				const defaultPort = DEFAULT_PORTS[instance.Engine];
				const isUsingDefaultPort = defaultPort === instance.Endpoint.Port;

				results.checks.push({
					resourceName: instance.DBInstanceIdentifier,
					resourceArn: instance.DBInstanceArn,
					status: isUsingDefaultPort ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
					message: isUsingDefaultPort
						? `Instance uses default port ${defaultPort} for engine ${instance.Engine}`
						: undefined
				});
			}

			marker = response.Marker;
		} while (marker);
	} catch (error) {
		results.checks = [
			{
				resourceName: "RDS Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking RDS instances: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkRdsDefaultPorts(region);
	printSummary(generateSummary(results));
}

export default {
	title: "RDS instances should not use a database engine default port",
	description:
		"RDS instances must use non-default database engine ports to enhance security by avoiding predictable port configurations.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.23",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsDefaultPorts
} satisfies RuntimeTest;
