import { IAMClient, ListServerCertificatesCommand } from "@aws-sdk/client-iam";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkExpiredCertificates(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new IAMClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const command = new ListServerCertificatesCommand({});
		const response = await client.send(command);

		if (
			!response.ServerCertificateMetadataList ||
			response.ServerCertificateMetadataList.length === 0
		) {
			results.checks = [
				{
					resourceName: "No SSL/TLS Certificates",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No SSL/TLS certificates found in IAM storage"
				}
			];
			return results;
		}

		const currentDate = new Date();

		for (const cert of response.ServerCertificateMetadataList) {
			if (!cert.ServerCertificateName || !cert.Arn) {
				results.checks.push({
					resourceName: "Unknown Certificate",
					status: ComplianceStatus.ERROR,
					message: "Certificate found without name or ARN"
				});
				continue;
			}

			const isExpired = cert.Expiration && new Date(cert.Expiration) < currentDate;

			results.checks.push({
				resourceName: cert.ServerCertificateName,
				resourceArn: cert.Arn,
				status: isExpired ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: isExpired ? `Certificate expired on ${cert.Expiration}` : undefined
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "IAM Certificate Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking SSL/TLS certificates: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkExpiredCertificates(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed",
	description:
		"To enable HTTPS connections to your website or application in AWS, you need an SSL/TLS server certificate. You can use ACM or IAM to store and deploy server certificates. Use IAM as a certificate manager only when you must support HTTPS connections in a region that is not supported by ACM. IAM securely encrypts your private keys and stores the encrypted version in IAM SSL certificate storage. IAM supports deploying server certificates in all regions, but you must obtain your certificate from an external provider for use with AWS. You cannot upload an ACM certificate to IAM. Additionally, you cannot manage your certificates from the IAM Console.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_IAM.4",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkExpiredCertificates,
	serviceName: "Amazon Identity and Access Management (IAM)",
	shortServiceName: "iam"
} satisfies RuntimeTest;
