import { AccessApprovalClient } from "@google-cloud/access-approval";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check if access approval is properly configured
function isProperlyConfigured(settings: any): boolean {
	return (
		settings.enrolledServices?.some(
			(service: any) => service.cloudProduct === "all" && service.enrollmentLevel === "BLOCK_ALL"
		) && settings.notificationEmails?.length > 0
	);
}

// Main compliance check function
export async function checkAccessApprovalEnabled(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const client = new AccessApprovalClient();
	const results: ComplianceReport = {
		checks: []
	};

	if (!projectId) {
		results.checks.push({
			resourceName: "Access Approval Check",
			status: ComplianceStatus.ERROR,
			message: "Project ID is not provided"
		});
		return results;
	}

	try {
		// Get access approval settings
		const [settings] = await client.getAccessApprovalSettings({
			name: `projects/${projectId}/accessApprovalSettings`
		});

		if (!settings) {
			results.checks.push({
				resourceName: `projects/${projectId}/accessApprovalSettings`,
				status: ComplianceStatus.FAIL,
				message: "Access Approval is not enabled for the project"
			});
			return results;
		}

		results.checks.push({
			resourceName: `projects/${projectId}/accessApprovalSettings`,
			resourceArn: settings.name ?? undefined,
			status: isProperlyConfigured(settings) ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
			message: !isProperlyConfigured(settings)
				? 'Access Approval must be enabled with proper configuration: enrolled_services set to "all" with BLOCK_ALL enrollment level and notification_emails configured'
				: undefined
		});
	} catch (error) {
		results.checks.push({
			resourceName: "Access Approval Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking Access Approval settings: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const results = await checkAccessApprovalEnabled(projectId);
	printSummary(generateSummary(results));
}

// Export default with compliance check metadata
export default {
	title: "Ensure 'Access Approval' is 'Enabled'",
	description:
		"GCP Access Approval enables you to require your organizations' explicit approval whenever Google support try to access your projects. This adds an additional control and logging of who in your organization approved/denied these requests.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.15",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	serviceName: "Access Approval",
	shortServiceName: "access-approval",
	execute: checkAccessApprovalEnabled
} satisfies RuntimeTest;
