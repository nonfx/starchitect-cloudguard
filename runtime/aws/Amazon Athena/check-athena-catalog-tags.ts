import {
	AthenaClient,
	ListDataCatalogsCommand,
	ListTagsForResourceCommand
} from "@aws-sdk/client-athena";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkAthenaCatalogTags(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new AthenaClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let nextToken: string | undefined;
		let catalogsFound = false;

		do {
			const command = new ListDataCatalogsCommand({
				NextToken: nextToken
			});

			const response = await client.send(command);

			if (!response.DataCatalogsSummary || response.DataCatalogsSummary.length === 0) {
				if (!catalogsFound) {
					results.checks.push({
						resourceName: "No Athena Data Catalogs",
						status: ComplianceStatus.NOTAPPLICABLE,
						message: "No Athena data catalogs found in the region"
					});
					return results;
				}
				break;
			}

			catalogsFound = true;

			for (const catalog of response.DataCatalogsSummary) {
				if (!catalog.CatalogName) {
					results.checks.push({
						resourceName: "Unknown Catalog",
						status: ComplianceStatus.ERROR,
						message: "Data catalog found without name"
					});
					continue;
				}

				// Get tags for the catalog using the standard Athena data catalog ARN format
				const tagsResponse = await client.send(
					new ListTagsForResourceCommand({
						ResourceARN: `arn:aws:athena:${region}:${process.env.AWS_ACCOUNT_ID}:datacatalog/${catalog.CatalogName}`
					})
				);

				// Check if catalog has any non-system tags
				const tags = tagsResponse.Tags ?? [];
				const nonSystemTags = tags.filter(tag => !tag.Key?.startsWith("aws:"));

				results.checks.push({
					resourceName: catalog.CatalogName,
					status: nonSystemTags.length > 0 ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message:
						nonSystemTags.length === 0
							? "Data catalog does not have any non-system tags"
							: undefined
				});
			}

			nextToken = response.NextToken;
		} while (nextToken);
	} catch (error) {
		results.checks.push({
			resourceName: "Athena Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking Athena data catalogs: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkAthenaCatalogTags(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Athena data catalogs should be tagged",
	description:
		"This control checks whether an Amazon Athena data catalog has tags with the specific keys defined in the parameter requiredTagKeys. The control fails if the data catalog doesn't have any tag keys or if it doesn't have all the keys specified in the parameter requiredTagKeys. If the parameter requiredTagKeys isn't provided, the control only checks for the existence of a tag key and fails if the data catalog isn't tagged with any key. System tags, which are automatically applied and begin with aws:, are ignored. A tag is a label that you assign to an AWS resource, and it consists of a key and an optional value. You can create tags to categorize resources by purpose, owner, environment, or other criteria. Tags can help you identify, organize, search for, and filter resources. Tagging also helps you track accountable resource owners for actions and notifications. When you use tagging, you can implement attribute-based access control (ABAC) as an authorization strategy, which defines permissions based on tags. You can attach tags to IAM entities (users or roles) and to AWS resources. You can create a single ABAC policy or a separate set of policies for your IAM principals. You can design these ABAC policies to allow operations when the principal's tag matches the resource tag",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_Athena.2",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "LOW",
	execute: checkAthenaCatalogTags,
	serviceName: "Amazon Athena",
	shortServiceName: "athena"
} satisfies RuntimeTest;
