// @ts-nocheck
import { IAMClient, ListPoliciesCommand, GetPolicyVersionCommand } from "@aws-sdk/client-iam";
import { TimestreamWriteClient, ListDatabasesCommand } from "@aws-sdk/client-timestream-write";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkTimestreamAccessControl from "./check-timestream-access-control";

const mockIAMClient = mockClient(IAMClient);
const mockTimestreamClient = mockClient(TimestreamWriteClient);

const mockDatabase = {
	DatabaseName: "test-database",
	Arn: "arn:aws:timestream:us-east-1:123456789012:database/test-database"
};

const mockPolicyForDatabase = {
	Version: "2012-10-17",
	Statement: [
		{
			Effect: "Allow",
			Action: ["timestream:DescribeDatabase", "timestream:ListTables"],
			Resource: "arn:aws:timestream:us-east-1:123456789012:database/test-database"
		}
	]
};

const mockPolicyForOtherResource = {
	Version: "2012-10-17",
	Statement: [
		{
			Effect: "Allow",
			Action: ["timestream:DescribeDatabase"],
			Resource: "arn:aws:timestream:us-east-1:123456789012:database/other-database"
		}
	]
};

describe("checkTimestreamAccessControl", () => {
	beforeEach(() => {
		mockIAMClient.reset();
		mockTimestreamClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when a policy exists for the database", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: [mockDatabase]
			});

			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [
					{
						Arn: "arn:aws:iam::123456789012:policy/test-policy",
						DefaultVersionId: "v1"
					}
				]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: encodeURIComponent(JSON.stringify(mockPolicyForDatabase))
				}
			});

			const result = await checkTimestreamAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-database");
			expect(result.checks[0].message).toBe("Policy found for the database");
		});

		it("should return NOTAPPLICABLE when no databases exist", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: []
			});

			const result = await checkTimestreamAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Timestream databases found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no policy exists for the database", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: [mockDatabase]
			});

			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [
					{
						Arn: "arn:aws:iam::123456789012:policy/test-policy",
						DefaultVersionId: "v1"
					}
				]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: encodeURIComponent(JSON.stringify(mockPolicyForOtherResource))
				}
			});

			const result = await checkTimestreamAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No policy found for the database");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListDatabases fails", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).rejects(new Error("Failed to list databases"));

			const result = await checkTimestreamAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to list databases");
		});

		it("should return ERROR when IAM operations fail", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: [mockDatabase]
			});

			mockIAMClient.on(ListPoliciesCommand).rejects(new Error("Failed to list policies"));

			const result = await checkTimestreamAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to list policies");
		});
	});
});
