// @ts-nocheck
import {
	AthenaClient,
	ListWorkGroupsCommand,
	ListTagsForResourceCommand
} from "@aws-sdk/client-athena";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkAthenaWorkgroupTags from "./check-athena-workgroup-tags";

const mockAthenaClient = mockClient(AthenaClient);

const mockWorkgroups = [{ Name: "workgroup-1" }, { Name: "workgroup-2" }];

describe("checkAthenaWorkgroupTags", () => {
	beforeEach(() => {
		mockAthenaClient.reset();
		process.env.AWS_ACCOUNT_ID = "123456789012";
	});

	describe("Compliant Resources", () => {
		it("should return PASS when workgroups have non-system tags", async () => {
			mockAthenaClient.on(ListWorkGroupsCommand).resolves({ WorkGroups: mockWorkgroups });

			mockAthenaClient.on(ListTagsForResourceCommand).resolves({
				Tags: [
					{ Key: "environment", Value: "production" },
					{ Key: "aws:created", Value: "system" } // System tag should be ignored
				]
			});

			const result = await checkAthenaWorkgroupTags.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});

		it("should handle pagination correctly", async () => {
			mockAthenaClient
				.on(ListWorkGroupsCommand)
				.resolvesOnce({
					WorkGroups: [mockWorkgroups[0]],
					NextToken: "token1"
				})
				.resolvesOnce({
					WorkGroups: [mockWorkgroups[1]]
				});

			mockAthenaClient.on(ListTagsForResourceCommand).resolves({
				Tags: [{ Key: "environment", Value: "production" }]
			});

			const result = await checkAthenaWorkgroupTags.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when workgroups have no tags", async () => {
			mockAthenaClient.on(ListWorkGroupsCommand).resolves({ WorkGroups: mockWorkgroups });

			mockAthenaClient.on(ListTagsForResourceCommand).resolves({ Tags: [] });

			const result = await checkAthenaWorkgroupTags.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Workgroup does not have any non-system tags");
		});

		it("should return FAIL when workgroups only have system tags", async () => {
			mockAthenaClient.on(ListWorkGroupsCommand).resolves({ WorkGroups: mockWorkgroups });

			mockAthenaClient.on(ListTagsForResourceCommand).resolves({
				Tags: [{ Key: "aws:created", Value: "system" }]
			});

			const result = await checkAthenaWorkgroupTags.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no workgroups exist", async () => {
			mockAthenaClient.on(ListWorkGroupsCommand).resolves({ WorkGroups: [] });

			const result = await checkAthenaWorkgroupTags.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Athena workgroups found in the region");
		});

		it("should return ERROR when ListWorkGroups fails", async () => {
			mockAthenaClient.on(ListWorkGroupsCommand).rejects(new Error("API Error"));

			const result = await checkAthenaWorkgroupTags.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Athena workgroups");
		});

		it("should return ERROR when ListTagsForResource fails", async () => {
			mockAthenaClient.on(ListWorkGroupsCommand).resolves({ WorkGroups: mockWorkgroups });

			mockAthenaClient.on(ListTagsForResourceCommand).rejects(new Error("Access Denied"));

			const result = await checkAthenaWorkgroupTags.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking tags");
		});

		it("should handle workgroups without names", async () => {
			mockAthenaClient.on(ListWorkGroupsCommand).resolves({ WorkGroups: [{}] });

			const result = await checkAthenaWorkgroupTags.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Workgroup found without name");
		});
	});
});
