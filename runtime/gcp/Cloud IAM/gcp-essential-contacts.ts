import { EssentialContactsServiceClient } from "@google-cloud/essential-contacts";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Helper function to check if notification categories are properly configured
function hasRequiredCategories(contacts: any[]): boolean {
	const requiredCategories = ["LEGAL", "SECURITY", "SUSPENSION", "TECHNICAL"];
	const configuredCategories = new Set<string>();

	for (const contact of contacts) {
		// If ALL category is configured, all requirements are met
		if (contact.notificationCategorySubscriptions?.includes("ALL")) {
			return true;
		}

		// Add configured categories to set
		contact.notificationCategorySubscriptions?.forEach((category: string) => {
			configuredCategories.add(category);
		});
	}

	// Check if all required categories are configured
	return requiredCategories.every(category => configuredCategories.has(category));
}

// Main compliance check function
export async function checkEssentialContacts(
	organizationId: string = process.env.GCP_ORGANIZATION_ID || ""
): Promise<ComplianceReport> {
	const client = new EssentialContactsServiceClient();
	const results: ComplianceReport = {
		checks: []
	};

	if (!organizationId) {
		results.checks.push({
			resourceName: "Essential Contacts Check",
			status: ComplianceStatus.ERROR,
			message: "Organization ID is not provided"
		});
		return results;
	}

	try {
		// List all essential contacts for the organization
		const [contacts] = await client.listContacts({
			parent: `organizations/${organizationId}`
		});

		// No contacts found
		if (!contacts || contacts.length === 0) {
			results.checks.push({
				resourceName: "Essential Contacts",
				status: ComplianceStatus.FAIL,
				message: "No essential contacts configured for the organization"
			});
			return results;
		}

		// Check if required notification categories are configured
		results.checks.push({
			resourceName: `Organization ${organizationId}`,
			status: hasRequiredCategories(contacts) ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
			message: hasRequiredCategories(contacts)
				? undefined
				: "Essential contacts missing required notification categories (Legal, Security, Suspension, Technical)"
		});
	} catch (error) {
		results.checks.push({
			resourceName: "Essential Contacts Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking essential contacts: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

// Main execution if run directly
if (import.meta.main) {
	const organizationId = process.env.GCP_ORGANIZATION_ID;
	const results = await checkEssentialContacts(organizationId);
	printSummary(generateSummary(results));
}

// Export default with compliance check metadata
export default {
	title: "Ensure Essential Contacts is Configured for Organization",
	description:
		"It is recommended that Essential Contacts is configured to designate email addresses for Google Cloud services to notify of important technical or security information.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_1.16",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	serviceName: "Cloud IAM",
	shortServiceName: "iam",
	execute: checkEssentialContacts
} satisfies RuntimeTest;
