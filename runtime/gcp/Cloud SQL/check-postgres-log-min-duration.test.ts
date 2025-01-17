// @ts-nocheck
import { sqladmin_v1 } from "@googleapis/sqladmin";
import { ComplianceStatus } from "../../types.js";
import { jest, describe, it, expect, beforeEach } from "@jest/globals";
import checkPostgresLogMinDuration from "./check-postgres-log-min-duration";

describe("checkPostgresLogMinDuration", () => {
	let mockList: jest.Mock;

	beforeEach(() => {
		jest.clearAllMocks();
		mockList = jest.fn();
		const mockSqladmin = {
			instances: {
				list: mockList
			}
		};
		(sqladmin_v1.Sqladmin as jest.Mock) = jest.fn(() => mockSqladmin);

		mockList.mockImplementation(async () => ({
			data: {
				kind: "sql#instancesList",
				items: []
			},
			status: 200,
			statusText: "OK",
			headers: {},
			config: {
				url: "https://sqladmin.googleapis.com/sql/v1/projects/test-project/instances",
				method: "GET"
			},
			request: {
				responseURL: "https://sqladmin.googleapis.com/sql/v1/projects/test-project/instances"
			}
		}));
	});

	describe("Compliant Resources", () => {
		it("should return PASS when log_min_duration_statement is set to -1", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "test-postgres-instance",
							databaseVersion: "POSTGRES_14",
							settings: {
								databaseFlags: [{ name: "log_min_duration_statement", value: "-1" }]
							}
						} as sqladmin_v1.Schema$DatabaseInstance
					]
				},
				status: 200,
				statusText: "OK",
				headers: {},
				config: {
					url: "https://sqladmin.googleapis.com/sql/v1/projects/test-project/instances",
					method: "GET"
				},
				request: {
					responseURL: "https://sqladmin.googleapis.com/sql/v1/projects/test-project/instances"
				}
			}));

			const result = await checkPostgresLogMinDuration.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-postgres-instance");
		});

		it("should return NOTAPPLICABLE when no SQL instances exist", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: []
				},
				status: 200,
				statusText: "OK",
				headers: {},
				config: {
					url: "https://sqladmin.googleapis.com/sql/v1/projects/test-project/instances",
					method: "GET"
				},
				request: {
					responseURL: "https://sqladmin.googleapis.com/sql/v1/projects/test-project/instances"
				}
			}));

			const result = await checkPostgresLogMinDuration.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No Cloud SQL instances found in the project");
		});

		it("should skip non-PostgreSQL instances", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "test-mysql-instance",
							databaseVersion: "MYSQL_8_0",
							settings: {
								databaseFlags: []
							}
						} as sqladmin_v1.Schema$DatabaseInstance
					]
				},
				status: 200,
				statusText: "OK",
				headers: {},
				config: {
					url: "https://sqladmin.googleapis.com/sql/v1/projects/test-project/instances",
					method: "GET"
				},
				request: {
					responseURL: "https://sqladmin.googleapis.com/sql/v1/projects/test-project/instances"
				}
			}));

			const result = await checkPostgresLogMinDuration.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("Not a PostgreSQL instance");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when log_min_duration_statement is not set to -1", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "test-postgres-instance",
							databaseVersion: "POSTGRES_14",
							settings: {
								databaseFlags: [{ name: "log_min_duration_statement", value: "1000" }]
							}
						} as sqladmin_v1.Schema$DatabaseInstance
					]
				},
				status: 200,
				statusText: "OK",
				headers: {},
				config: {
					url: "https://sqladmin.googleapis.com/sql/v1/projects/test-project/instances",
					method: "GET"
				},
				request: {
					responseURL: "https://sqladmin.googleapis.com/sql/v1/projects/test-project/instances"
				}
			}));

			const result = await checkPostgresLogMinDuration.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"log_min_duration_statement flag is not set to '-1'. To fix this, set the log_min_duration_statement database flag to '-1' in the instance settings. See: https://cloud.google.com/sql/docs/postgres/flags"
			);
		});

		it("should return FAIL when log_min_duration_statement is missing", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "test-postgres-instance",
							databaseVersion: "POSTGRES_14",
							settings: {
								databaseFlags: []
							}
						} as sqladmin_v1.Schema$DatabaseInstance
					]
				},
				status: 200,
				statusText: "OK",
				headers: {},
				config: {
					url: "https://sqladmin.googleapis.com/sql/v1/projects/test-project/instances",
					method: "GET"
				},
				request: {
					responseURL: "https://sqladmin.googleapis.com/sql/v1/projects/test-project/instances"
				}
			}));

			const result = await checkPostgresLogMinDuration.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"log_min_duration_statement flag is not set to '-1'. To fix this, set the log_min_duration_statement database flag to '-1' in the instance settings. See: https://cloud.google.com/sql/docs/postgres/flags"
			);
		});

		it("should handle multiple instances with mixed compliance", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "compliant-instance",
							databaseVersion: "POSTGRES_14",
							settings: {
								databaseFlags: [{ name: "log_min_duration_statement", value: "-1" }]
							}
						} as sqladmin_v1.Schema$DatabaseInstance,
						{
							name: "non-compliant-instance",
							databaseVersion: "POSTGRES_14",
							settings: {
								databaseFlags: [{ name: "log_min_duration_statement", value: "0" }]
							}
						} as sqladmin_v1.Schema$DatabaseInstance
					]
				},
				status: 200,
				statusText: "OK",
				headers: {},
				config: {
					url: "https://sqladmin.googleapis.com/sql/v1/projects/test-project/instances",
					method: "GET"
				},
				request: {
					responseURL: "https://sqladmin.googleapis.com/sql/v1/projects/test-project/instances"
				}
			}));

			const result = await checkPostgresLogMinDuration.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockList.mockImplementation(async () => {
				throw new Error("API Error");
			});

			const result = await checkPostgresLogMinDuration.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error listing SQL instances");
		});

		it("should handle non-Error exceptions", async () => {
			mockList.mockImplementation(async () => {
				throw "Unknown error";
			});

			const result = await checkPostgresLogMinDuration.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error listing SQL instances: Unknown error");
		});

		it("should handle instances with missing required fields", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							databaseVersion: "POSTGRES_14"
							// Missing name
						} as sqladmin_v1.Schema$DatabaseInstance
					]
				},
				status: 200,
				statusText: "OK",
				headers: {},
				config: {
					url: "https://sqladmin.googleapis.com/sql/v1/projects/test-project/instances",
					method: "GET"
				},
				request: {
					responseURL: "https://sqladmin.googleapis.com/sql/v1/projects/test-project/instances"
				}
			}));

			const result = await checkPostgresLogMinDuration.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Instance missing name or database version");
		});
	});
});
