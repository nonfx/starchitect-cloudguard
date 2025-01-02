import { LambdaClient, ListFunctionsCommand, GetFunctionCommand } from "@aws-sdk/client-lambda";
import type { FunctionConfiguration } from "@aws-sdk/client-lambda";
import { SecretsManagerClient, ListSecretsCommand } from "@aws-sdk/client-secrets-manager";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface LambdaEnvironment {
	Variables?: Record<string, string>;
}

function isDbCredential(key: string): boolean {
	const sensitivePatterns = [
		// Database related
		"DB_",
		"DATABASE_",
		"MYSQL_",
		"POSTGRES_",
		"MONGO_",
		"REDIS_",
		// Authentication/Secrets
		"PASSWORD",
		"SECRET",
		"AUTH_",
		"TOKEN_",
		"KEY_",
		"CERT_",
		// API Keys
		"API_KEY",
		"APIKEY",
		"CLIENT_SECRET",
		// Credentials
		"CREDENTIAL",
		"LOGIN",
		"PASS_",
		// Access tokens
		"ACCESS_TOKEN",
		"REFRESH_TOKEN",
		"BEARER_",
		// Private keys
		"PRIVATE_KEY",
		"SSH_KEY",
		"RSA_",
		// Other sensitive info
		"SALT_",
		"HASH_",
		"ENCRYPT_"
	];

	return sensitivePatterns.some(pattern => key.toUpperCase().includes(pattern));
}

async function checkLambdaSecretsManagerCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const lambdaClient = new LambdaClient({ region });
	const secretsClient = new SecretsManagerClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Helper function to get all Lambda functions with pagination
		async function getAllFunctions() {
			const allFunctions: FunctionConfiguration[] = [];
			let marker: string | undefined;

			do {
				const response = await lambdaClient.send(
					new ListFunctionsCommand({
						Marker: marker
					})
				);
				if (response.Functions) {
					allFunctions.push(...response.Functions);
				}
				marker = response.NextMarker;
			} while (marker);

			return allFunctions;
		}

		// Get all Lambda functions using pagination
		const allFunctions = await getAllFunctions();

		if (!allFunctions.length) {
			results.checks = [
				{
					resourceName: "No Lambda Functions",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Lambda functions found in the region"
				}
			];
			return results;
		}

		// Helper function to get all secrets with pagination
		async function getAllSecrets() {
			const allSecrets = new Set<string>();
			let nextToken: string | undefined;

			do {
				const response = await secretsClient.send(
					new ListSecretsCommand({
						NextToken: nextToken
					})
				);
				response.SecretList?.forEach(secret => {
					if (secret.ARN) allSecrets.add(secret.ARN);
				});
				nextToken = response.NextToken;
			} while (nextToken);

			return allSecrets;
		}

		// Get all Secrets Manager secrets using pagination
		const secretArns = await getAllSecrets();

		for (const func of allFunctions) {
			if (!func.FunctionName) {
				results.checks.push({
					resourceName: "Unknown Function",
					status: ComplianceStatus.ERROR,
					message: "Lambda function found without name"
				});
				continue;
			}

			try {
				const functionDetails = await lambdaClient.send(
					new GetFunctionCommand({
						FunctionName: func.FunctionName
					})
				);

				const environment = functionDetails.Configuration?.Environment as
					| LambdaEnvironment
					| undefined;
				const variables = environment?.Variables || {};

				let hasDbCredentials = false;
				let usesSecretsManager = true;

				for (const [key, value] of Object.entries(variables)) {
					if (isDbCredential(key)) {
						hasDbCredentials = true;
						// Check if the value references a Secrets Manager ARN
						if (
							!Array.from(secretArns).some(arn => typeof value === "string" && value.includes(arn))
						) {
							usesSecretsManager = false;
							break;
						}
					}
				}

				if (hasDbCredentials) {
					results.checks.push({
						resourceName: func.FunctionName,
						resourceArn: func.FunctionArn,
						status: usesSecretsManager ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: usesSecretsManager
							? undefined
							: "Lambda function contains database credentials not managed by Secrets Manager"
					});
				} else {
					results.checks.push({
						resourceName: func.FunctionName,
						resourceArn: func.FunctionArn,
						status: ComplianceStatus.NOTAPPLICABLE,
						message: "No database credentials found in Lambda environment variables"
					});
				}
			} catch (error) {
				results.checks.push({
					resourceName: func.FunctionName,
					resourceArn: func.FunctionArn,
					status: ComplianceStatus.ERROR,
					message: `Error checking function configuration: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Lambda Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Lambda functions: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkLambdaSecretsManagerCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "AWS Lambda",
	shortServiceName: "lambda",
	title: "Ensure AWS Secrets manager is configured and being used by Lambda for databases",
	description:
		"Lambda functions often have to access a database or other services within your environment.",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_4.3",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkLambdaSecretsManagerCompliance
} satisfies RuntimeTest;
