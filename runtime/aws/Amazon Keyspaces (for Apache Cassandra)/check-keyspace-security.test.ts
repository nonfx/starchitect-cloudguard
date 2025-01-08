// @ts-nocheck
import {
	KeyspacesClient,
	ListKeyspacesCommand,
	GetKeyspaceCommand
} from "@aws-sdk/client-keyspaces";
import { CloudWatchLogsClient, DescribeLogGroupsCommand } from "@aws-sdk/client-cloudwatch-logs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkKeyspaceSecurityConfiguration from "./check-keyspace-security";

const mockKeyspacesClient = mockClient(KeyspacesClient);
const mockCloudWatchClient = mockClient(CloudWatchLogsClient);

const mockKeyspace = {
	keyspaceName: "test-keyspace-1",
	resourceArn: "arn:aws:cassandra:us-east-1:123456789012:keyspace/test-keyspace-1"
};

const mockLogGroups = {
	logGroups: [
		{
			logGroupName: "/aws/keyspaces/test-keyspace-1",
			arn: "arn:aws:logs:us-east-1:123456789012:log-group:/aws/keyspaces/test-keyspace-1"
		}
	]
};

describe("checkKeyspaceSecurityConfiguration", () => {
	beforeEach(() => {
		mockKeyspacesClient.reset();
		mockCloudWatchClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when all security features are configured", async () => {
			mockKeyspacesClient
				.on(ListKeyspacesCommand)
				.resolves({ keyspaces: [mockKeyspace] })
				.on(GetKeyspaceCommand)
				.resolves({ keyspaceName: mockKeyspace.keyspaceName });

			mockCloudWatchClient.on(DescribeLogGroupsCommand).resolves(mockLogGroups);

			const result = await checkKeyspaceSecurityConfiguration.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-keyspace-1");
		});

		it("should return NOTAPPLICABLE when no keyspaces exist", async () => {
			mockKeyspacesClient.on(ListKeyspacesCommand).resolves({ keyspaces: [] });

			const result = await checkKeyspaceSecurityConfiguration.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Keyspaces found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when CloudWatch logs are not configured", async () => {
			mockKeyspacesClient
				.on(ListKeyspacesCommand)
				.resolves({ keyspaces: [mockKeyspace] })
				.on(GetKeyspaceCommand)
				.resolves({ keyspaceName: mockKeyspace.keyspaceName });

			mockCloudWatchClient.on(DescribeLogGroupsCommand).resolves({ logGroups: [] });

			const result = await checkKeyspaceSecurityConfiguration.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("CloudWatch logging not configured");
		});

		it("should skip keyspaces without names", async () => {
			const validKeyspace = {
				keyspaceName: "valid-keyspace",
				resourceArn: "arn:aws:cassandra:us-east-1:123456789012:keyspace/valid-keyspace"
			};

			mockKeyspacesClient
				.on(ListKeyspacesCommand)
				.resolves({
					keyspaces: [
						{ resourceArn: "some-arn" }, // Invalid keyspace
						validKeyspace // Valid keyspace
					]
				})
				.on(GetKeyspaceCommand)
				.resolves({ keyspaceName: validKeyspace.keyspaceName });

			mockCloudWatchClient.on(DescribeLogGroupsCommand).resolves({ logGroups: [] });

			const result = await checkKeyspaceSecurityConfiguration.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].resourceName).toBe("valid-keyspace");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListKeyspaces fails", async () => {
			mockKeyspacesClient.on(ListKeyspacesCommand).rejects(new Error("API Error"));

			const result = await checkKeyspaceSecurityConfiguration.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking keyspaces security");
		});

		it("should handle CloudWatch API errors", async () => {
			mockKeyspacesClient
				.on(ListKeyspacesCommand)
				.resolves({ keyspaces: [mockKeyspace] })
				.on(GetKeyspaceCommand)
				.resolves({ keyspaceName: mockKeyspace.keyspaceName });

			mockCloudWatchClient.on(DescribeLogGroupsCommand).rejects(new Error("CloudWatch API Error"));

			const result = await checkKeyspaceSecurityConfiguration.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking keyspace security");
		});

		it("should handle GetKeyspace errors", async () => {
			mockKeyspacesClient
				.on(ListKeyspacesCommand)
				.resolves({ keyspaces: [mockKeyspace] })
				.on(GetKeyspaceCommand)
				.rejects(new Error("Keyspace API Error"));

			const result = await checkKeyspaceSecurityConfiguration.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking keyspace security");
		});
	});
});
