//@ts-nocheck
import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import { TimestreamWriteClient, ListDatabasesCommand } from "@aws-sdk/client-timestream-write";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkTimestreamMonitoring from "./check-timestream-monitoring";

const mockCloudWatchClient = mockClient(CloudWatchClient);
const mockTimestreamClient = mockClient(TimestreamWriteClient);

const mockDatabase1 = {
	DatabaseName: "test-db-1",
	Arn: "arn:aws:timestream:us-east-1:123456789012:database/test-db-1"
};

const mockDatabase2 = {
	DatabaseName: "test-db-2",
	Arn: "arn:aws:timestream:us-east-1:123456789012:database/test-db-2"
};

const mockAlarm = {
	AlarmName: "Timestream-Alarm",
	Namespace: "AWS/Timestream",
	Dimensions: [
		{
			Name: "DatabaseName",
			Value: "test-db-1"
		}
	]
};

describe("checkTimestreamMonitoring", () => {
	beforeEach(() => {
		mockCloudWatchClient.reset();
		mockTimestreamClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when databases have CloudWatch alarms configured", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: [mockDatabase1]
			});
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: [mockAlarm]
			});

			const result = await checkTimestreamMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-db-1");
			expect(result.checks[0].message).toContain("1 CloudWatch alarm(s) configured");
		});

		it("should return NOTAPPLICABLE when no Timestream databases exist", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: []
			});

			const result = await checkTimestreamMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Timestream databases found");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when databases have no CloudWatch alarms", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: [mockDatabase1]
			});
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: []
			});

			const result = await checkTimestreamMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No CloudWatch alarms configured for this Timestream database"
			);
		});

		it("should handle mixed compliance scenarios", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: [mockDatabase1, mockDatabase2]
			});
			mockCloudWatchClient.on(DescribeAlarmsCommand).resolves({
				MetricAlarms: [mockAlarm]
			});

			const result = await checkTimestreamMonitoring.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListDatabases fails", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).rejects(new Error("API Error"));

			const result = await checkTimestreamMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Timestream monitoring");
		});

		it("should handle CloudWatch API errors", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: [mockDatabase1]
			});
			mockCloudWatchClient.on(DescribeAlarmsCommand).rejects(new Error("CloudWatch API Error"));

			const result = await checkTimestreamMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
		});

		it("should handle pagination for CloudWatch alarms", async () => {
			mockTimestreamClient.on(ListDatabasesCommand).resolves({
				Databases: [mockDatabase1]
			});
			mockCloudWatchClient
				.on(DescribeAlarmsCommand)
				.resolvesOnce({
					MetricAlarms: [mockAlarm],
					NextToken: "token1"
				})
				.resolvesOnce({
					MetricAlarms: [mockAlarm]
				});

			const result = await checkTimestreamMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toContain("2 CloudWatch alarm(s) configured");
		});
	});
});
