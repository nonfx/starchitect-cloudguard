import { LambdaClient, ListFunctionsCommand, GetFunctionCommand } from "@aws-sdk/client-lambda";
import { EC2Client, DescribeSubnetsCommand } from "@aws-sdk/client-ec2";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

const MIN_AZ_COUNT = 2;

async function checkLambdaVpcMultiAzCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const lambdaClient = new LambdaClient({ region });
	const ec2Client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let nextMarker: string | undefined;
		let functionsFound = false;

		do {
			const listCommand = new ListFunctionsCommand({
				Marker: nextMarker
			});
			const response = await lambdaClient.send(listCommand);

			if (!response.Functions || response.Functions.length === 0) {
				if (!functionsFound) {
					results.checks = [
						{
							resourceName: "No Lambda Functions",
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "No Lambda functions found in the region"
						}
					];
					return results;
				}
				break;
			}

			functionsFound = true;

			for (const func of response.Functions) {
				if (!func.FunctionName) continue;

				try {
					const getFunctionCommand = new GetFunctionCommand({
						FunctionName: func.FunctionName
					});
					const functionDetails = await lambdaClient.send(getFunctionCommand);

					// Skip if function is not VPC-connected
					if (!functionDetails.Configuration?.VpcConfig?.SubnetIds?.length) {
						results.checks.push({
							resourceName: func.FunctionName,
							resourceArn: func.FunctionArn,
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "Function is not VPC-connected"
						});
						continue;
					}

					// Get subnet details to check AZs
					const describeSubnetsCommand = new DescribeSubnetsCommand({
						SubnetIds: functionDetails.Configuration.VpcConfig.SubnetIds
					});
					const subnetResponse = await ec2Client.send(describeSubnetsCommand);

					// Get unique AZs
					const uniqueAZs = new Set(subnetResponse.Subnets?.map(subnet => subnet.AvailabilityZone));

					const isCompliant = uniqueAZs.size >= MIN_AZ_COUNT;

					results.checks.push({
						resourceName: func.FunctionName,
						resourceArn: func.FunctionArn,
						status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: isCompliant
							? undefined
							: `Function uses ${uniqueAZs.size} AZ(s), minimum required is ${MIN_AZ_COUNT}`
					});
				} catch (error) {
					results.checks.push({
						resourceName: func.FunctionName,
						resourceArn: func.FunctionArn,
						status: ComplianceStatus.ERROR,
						message: `Error checking function: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			}

			nextMarker = response.NextMarker;
		} while (nextMarker);
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
	const results = await checkLambdaVpcMultiAzCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "AWS Lambda",
	shortServiceName: "lambda",
	title: "VPC Lambda functions should operate in multiple Availability Zones",
	description:
		"This control checks if Lambda functions connected to VPC operate in multiple Availability Zones for high availability and fault tolerance.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_Lambda.5",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkLambdaVpcMultiAzCompliance
} satisfies RuntimeTest;
