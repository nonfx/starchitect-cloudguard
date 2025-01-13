//@ts-nocheck
import {
	AthenaClient,
	ListDataCatalogsCommand,
	ListTagsForResourceCommand
} from "@aws-sdk/client-athena";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkAthenaCatalogTags from "./check-athena-catalog-tags";

const mockAthenaClient = mockClient(AthenaClient);

const mockCatalogWithTags = {
	CatalogName: "test-catalog-1"
};

const mockCatalogWithoutTags = {
	CatalogName: "test-catalog-2"
};

const mockCatalogWithSystemTags = {
	CatalogName: "test-catalog-3"
};

describe("checkAthenaCatalogTags", () => {
	beforeEach(() => {
		mockAthenaClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when catalog has non-system tags", async () => {
			mockAthenaClient
				.on(ListDataCatalogsCommand)
				.resolves({ DataCatalogsSummary: [mockCatalogWithTags] })
				.on(ListTagsForResourceCommand)
				.resolves({ Tags: [{ Key: "environment", Value: "production" }] });

			const result = await checkAthenaCatalogTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-catalog-1");
		});

		it("should handle multiple catalogs with mixed tag status", async () => {
			mockAthenaClient
				.on(ListDataCatalogsCommand)
				.resolves({ DataCatalogsSummary: [mockCatalogWithTags, mockCatalogWithoutTags] })
				.on(ListTagsForResourceCommand)
				.resolvesOnce({ Tags: [{ Key: "environment", Value: "production" }] }) // Tags for catalog 1
				.resolvesOnce({ Tags: [] }); // No tags for catalog 2

			const result = await checkAthenaCatalogTags.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when catalog has no tags", async () => {
			mockAthenaClient
				.on(ListDataCatalogsCommand)
				.resolves({ DataCatalogsSummary: [mockCatalogWithoutTags] })
				.on(ListTagsForResourceCommand)
				.resolves({ Tags: [] });

			const result = await checkAthenaCatalogTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Data catalog does not have any non-system tags");
		});

		it("should return FAIL when catalog only has system tags", async () => {
			mockAthenaClient
				.on(ListDataCatalogsCommand)
				.resolves({ DataCatalogsSummary: [mockCatalogWithSystemTags] })
				.on(ListTagsForResourceCommand)
				.resolves({ Tags: [{ Key: "aws:created", Value: "true" }] });

			const result = await checkAthenaCatalogTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no catalogs exist", async () => {
			mockAthenaClient.on(ListDataCatalogsCommand).resolves({ DataCatalogsSummary: [] });

			const result = await checkAthenaCatalogTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Athena data catalogs found in the region");
		});

		it("should handle catalog without name", async () => {
			mockAthenaClient.on(ListDataCatalogsCommand).resolves({ DataCatalogsSummary: [{}] });

			const result = await checkAthenaCatalogTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Data catalog found without name");
		});
	});

	describe("Pagination", () => {
		it("should handle paginated results", async () => {
			mockAthenaClient
				.on(ListDataCatalogsCommand)
				.resolvesOnce({
					DataCatalogsSummary: [mockCatalogWithTags],
					NextToken: "token1"
				})
				.resolvesOnce({
					DataCatalogsSummary: [mockCatalogWithoutTags]
				})
				.on(ListTagsForResourceCommand)
				.resolvesOnce({ Tags: [{ Key: "environment", Value: "production" }] }) // Tags for catalog 1
				.resolvesOnce({ Tags: [] }); // No tags for catalog 2

			const result = await checkAthenaCatalogTags.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockAthenaClient.on(ListDataCatalogsCommand).rejects(new Error("API Error"));

			const result = await checkAthenaCatalogTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Athena data catalogs: API Error");
		});
	});
});
