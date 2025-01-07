//@ts-nocheck
import { AthenaClient, ListWorkGroupsCommand, GetWorkGroupCommand } from "@aws-sdk/client-athena";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkAthenaWorkgroupEncryption from "./check-athena-workgroup-encryption";

const mockAthenaClient = mockClient(AthenaClient);

const mockWorkgroups = [{ Name: "workgroup-1" }, { Name: "workgroup-2" }];

describe("checkAthenaWorkgroupEncryption", () => {
	beforeEach(() => {
		mockAthenaClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for workgroups with SSE_S3 encryption", async () => {
			mockAthenaClient.on(ListWorkGroupsCommand).resolves({ WorkGroups: mockWorkgroups });
			mockAthenaClient.on(GetWorkGroupCommand).resolves({
				WorkGroup: {
					Configuration: {
						ResultConfiguration: {
							EncryptionConfiguration: {
								EncryptionOption: "SSE_S3"
							}
						}
					}
				}
			});

			const result = await checkAthenaWorkgroupEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});

		it("should return PASS for workgroups with SSE_KMS encryption and KMS key", async () => {
			mockAthenaClient.on(ListWorkGroupsCommand).resolves({ WorkGroups: [mockWorkgroups[0]] });
			mockAthenaClient.on(GetWorkGroupCommand).resolves({
				WorkGroup: {
					Configuration: {
						ResultConfiguration: {
							EncryptionConfiguration: {
								EncryptionOption: "SSE_KMS",
								KmsKey: "arn:aws:kms:region:account:key/key-id"
							}
						}
					}
				}
			});

			const result = await checkAthenaWorkgroupEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for workgroups without encryption", async () => {
			mockAthenaClient.on(ListWorkGroupsCommand).resolves({ WorkGroups: [mockWorkgroups[0]] });
			mockAthenaClient.on(GetWorkGroupCommand).resolves({
				WorkGroup: {
					Configuration: {
						ResultConfiguration: {}
					}
				}
			});

			const result = await checkAthenaWorkgroupEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("not encrypted at rest");
		});

		it("should return FAIL for workgroups with SSE_KMS but no KMS key", async () => {
			mockAthenaClient.on(ListWorkGroupsCommand).resolves({ WorkGroups: [mockWorkgroups[0]] });
			mockAthenaClient.on(GetWorkGroupCommand).resolves({
				WorkGroup: {
					Configuration: {
						ResultConfiguration: {
							EncryptionConfiguration: {
								EncryptionOption: "SSE_KMS"
							}
						}
					}
				}
			});

			const result = await checkAthenaWorkgroupEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no workgroups exist", async () => {
			mockAthenaClient.on(ListWorkGroupsCommand).resolves({ WorkGroups: [] });

			const result = await checkAthenaWorkgroupEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toContain("No Athena workgroups found");
		});

		it("should return ERROR when ListWorkGroups fails", async () => {
			mockAthenaClient.on(ListWorkGroupsCommand).rejects(new Error("API Error"));

			const result = await checkAthenaWorkgroupEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Athena workgroups");
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

			mockAthenaClient.on(GetWorkGroupCommand).resolves({
				WorkGroup: {
					Configuration: {
						ResultConfiguration: {
							EncryptionConfiguration: {
								EncryptionOption: "SSE_S3"
							}
						}
					}
				}
			});

			const result = await checkAthenaWorkgroupEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
		});
	});
});
