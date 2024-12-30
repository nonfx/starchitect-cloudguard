// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import {
	IAMClient,
	ListUsersCommand,
	GetLoginProfileCommand,
	ListAccessKeysCommand
} from "@aws-sdk/client-iam";
import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkPasswordRotation from "./check-rds-password-rotation";

const mockIAMClient = mockClient(IAMClient);
const mockRDSClient = mockClient(RDSClient);

const NOW = new Date("2024-01-01");
const OLD_DATE = new Date("2023-01-01"); // More than 90 days old
const RECENT_DATE = new Date("2023-12-01"); // Less than 90 days old

describe("checkPasswordRotation", () => {
	beforeEach(() => {
		mockIAMClient.reset();
		mockRDSClient.reset();
		jest.useFakeTimers();
		jest.setSystemTime(NOW);
	});

	afterAll(() => {
		jest.useRealTimers();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for users with recently rotated passwords and access keys", async () => {
			mockIAMClient
				.on(ListUsersCommand)
				.resolves({
					Users: [
						{
							UserName: "compliant-user",
							Arn: "arn:aws:iam::123456789012:user/compliant-user"
						}
					]
				})
				.on(GetLoginProfileCommand)
				.resolves({
					LoginProfile: { CreateDate: RECENT_DATE }
				})
				.on(ListAccessKeysCommand)
				.resolves({
					AccessKeyMetadata: [
						{
							AccessKeyId: "AKIA123456789",
							CreateDate: RECENT_DATE
						}
					]
				});

			const result = await checkPasswordRotation.execute("us-east-1");
			expect(result.checks.filter(c => c.status === ComplianceStatus.PASS)).toHaveLength(2);
		});

		it("should return NOTAPPLICABLE when no IAM users exist", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: [] });
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] });

			const result = await checkPasswordRotation.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for users with old passwords and access keys", async () => {
			mockIAMClient
				.on(ListUsersCommand)
				.resolves({
					Users: [
						{
							UserName: "non-compliant-user",
							Arn: "arn:aws:iam::123456789012:user/non-compliant-user"
						}
					]
				})
				.on(GetLoginProfileCommand)
				.resolves({
					LoginProfile: { CreateDate: OLD_DATE }
				})
				.on(ListAccessKeysCommand)
				.resolves({
					AccessKeyMetadata: [
						{
							AccessKeyId: "AKIA123456789",
							CreateDate: OLD_DATE
						}
					]
				});

			const result = await checkPasswordRotation.execute("us-east-1");
			expect(result.checks.filter(c => c.status === ComplianceStatus.FAIL)).toHaveLength(2);
		});

		it("should handle mixed compliance scenarios", async () => {
			mockIAMClient
				.on(ListUsersCommand)
				.resolves({
					Users: [
						{
							UserName: "mixed-user",
							Arn: "arn:aws:iam::123456789012:user/mixed-user"
						}
					]
				})
				.on(GetLoginProfileCommand)
				.resolves({
					LoginProfile: { CreateDate: RECENT_DATE }
				})
				.on(ListAccessKeysCommand)
				.resolves({
					AccessKeyMetadata: [
						{
							AccessKeyId: "AKIA123456789",
							CreateDate: OLD_DATE
						}
					]
				});

			const result = await checkPasswordRotation.execute("us-east-1");
			expect(result.checks.filter(c => c.status === ComplianceStatus.PASS)).toHaveLength(1);
			expect(result.checks.filter(c => c.status === ComplianceStatus.FAIL)).toHaveLength(1);
		});
	});

	describe("Aurora DB Instances", () => {
		it("should return INFO for Aurora instances", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: [] });
			mockRDSClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [
					{
						DBInstanceIdentifier: "aurora-instance",
						DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:aurora-instance",
						Engine: "aurora-postgresql"
					}
				]
			});

			const result = await checkPasswordRotation.execute("us-east-1");
			expect(result.checks.find(c => c.status === ComplianceStatus.INFO)).toBeTruthy();
		});
	});

	describe("Error Handling", () => {
		it("should handle IAM API errors", async () => {
			mockIAMClient.on(ListUsersCommand).rejects(new Error("IAM API Error"));

			const result = await checkPasswordRotation.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("IAM API Error");
		});

		it("should handle RDS API errors", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: [] });
			mockRDSClient.on(DescribeDBInstancesCommand).rejects(new Error("RDS API Error"));

			const result = await checkPasswordRotation.execute("us-east-1");
			expect(result.checks.find(c => c.message?.includes("RDS API Error"))).toBeTruthy();
		});
	});
});
