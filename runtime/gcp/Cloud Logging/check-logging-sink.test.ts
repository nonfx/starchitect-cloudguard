// @ts-nocheck
import logging from "@google-cloud/logging";
import { ComplianceStatus } from "../../types.js";
import checkLoggingSink from "./check-logging-sink.js";

describe("checkLoggingSink", () => {
	const mockListSinks = jest.fn().mockResolvedValue([[]]);

	beforeEach(() => {
		// Reset all mocks
		mockListSinks.mockClear();

		// Setup logging client mock
		logging.v2.ConfigServiceV2Client.prototype.listSinks = mockListSinks;
	});

	describe("Compliant Resources", () => {
		it("should return PASS when valid sink exists", async () => {
			const mockSinks = [
				{
					name: "test-sink",
					destination: "storage.googleapis.com/test-bucket",
					filter: undefined
				}
			];

			mockListSinks.mockResolvedValueOnce([mockSinks]);

			const result = await checkLoggingSink.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toBe(
				"Valid logging sink configured with destination: storage.googleapis.com/test-bucket"
			);
		});

		it("should accept BigQuery as a valid destination", async () => {
			const mockSinks = [
				{
					name: "test-sink",
					destination: "bigquery.googleapis.com/test-dataset",
					filter: undefined
				}
			];

			mockListSinks.mockResolvedValueOnce([mockSinks]);

			const result = await checkLoggingSink.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});

		it("should accept Pub/Sub as a valid destination", async () => {
			const mockSinks = [
				{
					name: "test-sink",
					destination: "pubsub.googleapis.com/test-topic",
					filter: undefined
				}
			];

			mockListSinks.mockResolvedValueOnce([mockSinks]);

			const result = await checkLoggingSink.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no sinks exist", async () => {
			mockListSinks.mockResolvedValueOnce([[]]);

			const result = await checkLoggingSink.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No logging sinks found - at least one sink must be configured to export all log entries"
			);
		});

		it("should return FAIL when sink has a filter", async () => {
			const mockSinks = [
				{
					name: "test-sink",
					destination: "storage.googleapis.com/test-bucket",
					filter: "severity >= WARNING"
				}
			];

			mockListSinks.mockResolvedValueOnce([mockSinks]);

			const result = await checkLoggingSink.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No logging sink found that exports all log entries to a valid destination"
			);
		});

		it("should return FAIL when sink has invalid destination", async () => {
			const mockSinks = [
				{
					name: "test-sink",
					destination: "invalid-destination",
					filter: undefined
				}
			];

			mockListSinks.mockResolvedValueOnce([mockSinks]);

			const result = await checkLoggingSink.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No logging sink found that exports all log entries to a valid destination"
			);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when listSinks fails", async () => {
			mockListSinks.mockRejectedValueOnce(new Error("API Error"));

			const result = await checkLoggingSink.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking logging sinks");
		});
	});
});
