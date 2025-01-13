//@ts-nocheck
import { AthenaClient, ListWorkGroupsCommand, GetWorkGroupCommand } from "@aws-sdk/client-athena";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkAthenaWorkgroupLogging from "./check-athena-workgroup-logging";

const mockAthenaClient = mockClient(AthenaClient);

const mockWorkgroups = [{ Name: "workgroup-1" }, { Name: "workgroup-2" }];

describe("checkAthenaWorkgroupLogging", () => {
	beforeEach(() => {
		mockAthenaClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when all workgroups have logging enabled", async () => {
			mockAthenaClient.on(ListWorkGroupsCommand).resolves({
				WorkGroups: mockWorkgroups
			});

			mockAthenaClient.on(GetWorkGroupCommand).resolves({
				WorkGroup: {
					Configuration: {
						PublishCloudWatchMetricsEnabled: true
					}
				}
			});

			const result = await checkAthenaWorkgroupLogging.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});

		it("should return NOTAPPLICABLE when no workgroups exist", async () => {
			mockAthenaClient.on(ListWorkGroupsCommand).resolves({
				WorkGroups: []
			});

			const result = await checkAthenaWorkgroupLogging.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Athena workgroups found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when workgroups have logging disabled", async () => {
			mockAthenaClient.on(ListWorkGroupsCommand).resolves({
				WorkGroups: mockWorkgroups
			});

			mockAthenaClient.on(GetWorkGroupCommand).resolves({
				WorkGroup: {
					Configuration: {
						PublishCloudWatchMetricsEnabled: false
					}
				}
			});

			const result = await checkAthenaWorkgroupLogging.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"CloudWatch metrics logging is not enabled for this workgroup"
			);
		});

		it("should handle mixed compliance states", async () => {
			mockAthenaClient.on(ListWorkGroupsCommand).resolves({
				WorkGroups: mockWorkgroups
			});

			mockAthenaClient
				.on(GetWorkGroupCommand, { WorkGroup: "workgroup-1" })
				.resolves({
					WorkGroup: {
						Configuration: {
							PublishCloudWatchMetricsEnabled: true
						}
					}
				})
				.on(GetWorkGroupCommand, { WorkGroup: "workgroup-2" })
				.resolves({
					WorkGroup: {
						Configuration: {
							PublishCloudWatchMetricsEnabled: false
						}
					}
				});

			const result = await checkAthenaWorkgroupLogging.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should handle ListWorkGroups API errors", async () => {
			mockAthenaClient.on(ListWorkGroupsCommand).rejects(new Error("API Error"));

			const result = await checkAthenaWorkgroupLogging.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Athena workgroups");
		});

		it("should handle GetWorkGroup API errors", async () => {
			mockAthenaClient.on(ListWorkGroupsCommand).resolves({
				WorkGroups: mockWorkgroups
			});

			mockAthenaClient.on(GetWorkGroupCommand).rejects(new Error("Access Denied"));

			const result = await checkAthenaWorkgroupLogging.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking workgroup configuration");
		});

		it("should handle pagination", async () => {
			mockAthenaClient
				.on(ListWorkGroupsCommand)
				.resolvesOnce({
					WorkGroups: [mockWorkgroups[0]],
					NextToken: "token1"
				})
				.resolvesOnce({
					WorkGroups: [mockWorkgroups[1]]
				});

			mockAthenaClient.on(GetWorkGroupCommand).resolves({
				WorkGroup: {
					Configuration: {
						PublishCloudWatchMetricsEnabled: true
					}
				}
			});

			const result = await checkAthenaWorkgroupLogging.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});
	});
});
