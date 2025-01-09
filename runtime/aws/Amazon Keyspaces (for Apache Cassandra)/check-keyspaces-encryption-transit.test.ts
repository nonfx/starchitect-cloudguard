//@ts-nocheck
import {
	KeyspacesClient,
	ListKeyspacesCommand,
	GetKeyspaceCommand
} from "@aws-sdk/client-keyspaces";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkKeyspacesEncryption from "./check-keyspaces-encryption-transit.js";

const mockKeyspacesClient = mockClient(KeyspacesClient);

describe("checkKeyspacesEncryptionInTransit", () => {
	beforeEach(() => {
		mockKeyspacesClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when keyspace has encryption configured", async () => {
			mockKeyspacesClient
				.on(ListKeyspacesCommand)
				.resolves({ keyspaces: [{ keyspaceName: "test-keyspace" }] })
				.on(GetKeyspaceCommand)
				.resolves({
					kmsKeyArn: "arn:aws:kms:region:account:key/test-key"
				});

			const result = await checkKeyspacesEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-keyspace");
		});

		it("should return NOTAPPLICABLE when no keyspaces exist", async () => {
			mockKeyspacesClient.on(ListKeyspacesCommand).resolves({ keyspaces: [] });

			const result = await checkKeyspacesEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Keyspaces found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should handle multiple keyspaces with mixed encryption settings", async () => {
			mockKeyspacesClient
				.on(ListKeyspacesCommand)
				.resolves({
					keyspaces: [{ keyspaceName: "ks1" }, { keyspaceName: "ks2" }]
				})
				.on(GetKeyspaceCommand, { keyspaceName: "ks1" })
				.resolves({
					kmsKeyArn: "arn:aws:kms:region:account:key/test-key"
				})
				.on(GetKeyspaceCommand, { keyspaceName: "ks2" })
				.resolves({});

			const result = await checkKeyspacesEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListKeyspaces fails", async () => {
			mockKeyspacesClient.on(ListKeyspacesCommand).rejects(new Error("Failed to list keyspaces"));

			const result = await checkKeyspacesEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking keyspaces encryption");
		});

		it("should handle error when GetKeyspace fails", async () => {
			mockKeyspacesClient
				.on(ListKeyspacesCommand)
				.resolves({ keyspaces: [{ keyspaceName: "test-keyspace" }] })
				.on(GetKeyspaceCommand)
				.rejects(new Error("Access denied"));

			const result = await checkKeyspacesEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking encryption configuration");
		});

		it("should skip keyspaces without names", async () => {
			mockKeyspacesClient
				.on(ListKeyspacesCommand)
				.resolves({
					keyspaces: [{ keyspaceName: undefined }, { keyspaceName: "valid-keyspace" }]
				})
				.on(GetKeyspaceCommand)
				.resolves({
					kmsKeyArn: "arn:aws:kms:region:account:key/test-key"
				});

			const result = await checkKeyspacesEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].resourceName).toBe("valid-keyspace");
		});
	});
});
