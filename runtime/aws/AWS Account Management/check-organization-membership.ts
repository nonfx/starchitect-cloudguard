import { OrganizationsClient, DescribeOrganizationCommand } from "@aws-sdk/client-organizations";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkOrganizationMembership(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new OrganizationsClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Attempt to describe the organization
		const command = new DescribeOrganizationCommand({});
		const response = await client.send(command);

		if (response.Organization) {
			results.checks.push({
				resourceName: "AWS Account",
				resourceArn: response.Organization.Arn,
				status: ComplianceStatus.PASS,
				message: `Account is part of organization ${response.Organization.Id}`
			});
		} else {
			results.checks.push({
				resourceName: "AWS Account",
				status: ComplianceStatus.FAIL,
				message: "Account is not part of an AWS Organization"
			});
		}
	} catch (error: any) {
		// If the error is AWSOrganizationsNotInUseException, the account is not part of an organization
		if (error.name === "AWSOrganizationsNotInUseException") {
			results.checks.push({
				resourceName: "AWS Account",
				status: ComplianceStatus.FAIL,
				message: "Account is not part of an AWS Organization"
			});
		} else {
			results.checks.push({
				resourceName: "AWS Account",
				status: ComplianceStatus.ERROR,
				message: `Error checking organization membership: ${error instanceof Error ? error.message : String(error)}`
			});
		}
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkOrganizationMembership(region);
	printSummary(generateSummary(results));
}

export default {
	title: "AWS accounts should be part of an AWS Organizations organization",
	description:
		"This control checks if an AWS account is part of an organization managed through AWS Organizations. The control fails if the account is not part of an organization. Organizations helps you centrally manage your environment as you scale your workloads on AWS. You can use multiple AWS accounts to isolate workloads that have specific security requirements, or to comply with frameworks such as HIPAA or PCI. By creating an organization, you can administer multiple accounts as a single unit and centrally manage their access to AWS services, resources, and Regions",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_Organizations.1",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkOrganizationMembership,
	serviceName: "AWS Organizations",
	shortServiceName: "organizations"
} satisfies RuntimeTest;
