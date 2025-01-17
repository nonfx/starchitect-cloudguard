// @ts-nocheck
import { sqladmin_v1 } from "@googleapis/sqladmin";
import { ComplianceStatus } from "../../types.js";
import { jest, describe, it, expect, beforeEach } from "@jest/globals";
import checkSqlContainedDbAuth from "./check-sql-contained-db-auth";

describe("checkSqlContainedDbAuth", () => {
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
		it("should return PASS when contained database authentication is disabled", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "sql-instance-1",
							databaseVersion: "SQLSERVER_2022_STANDARD",
							settings: {
								databaseFlags: [{ name: "contained database authentication", value: "off" }]
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

			const result = await checkSqlContainedDbAuth.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("sql-instance-1");
		});

		it("should handle multiple compliant instances", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "sql-instance-1",
							databaseVersion: "SQLSERVER_2022_STANDARD",
							settings: {
								databaseFlags: [{ name: "contained database authentication", value: "off" }]
							}
						} as sqladmin_v1.Schema$DatabaseInstance,
						{
							name: "sql-instance-2",
							databaseVersion: "SQLSERVER_2019_ENTERPRISE",
							settings: {
								databaseFlags: [{ name: "contained database authentication", value: "off" }]
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

			const result = await checkSqlContainedDbAuth.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.PASS);
		});

		it("should skip non-SQL Server instances", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "mysql-instance",
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

			const result = await checkSqlContainedDbAuth.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("Not a SQL Server instance");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when contained database authentication is enabled", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "sql-instance-2",
							databaseVersion: "SQLSERVER_2019_ENTERPRISE",
							settings: {
								databaseFlags: [{ name: "contained database authentication", value: "on" }]
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

			const result = await checkSqlContainedDbAuth.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"Contained database authentication is enabled. To fix this, set the 'contained database authentication' database flag to 'off' in the instance settings for better security. See: https://cloud.google.com/sql/docs/sqlserver/flags"
			);
		});

		it("should handle multiple instances with mixed compliance", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "sql-instance-3",
							databaseVersion: "SQLSERVER_2022_STANDARD",
							settings: {
								databaseFlags: [{ name: "contained database authentication", value: "on" }]
							}
						} as sqladmin_v1.Schema$DatabaseInstance,
						{
							name: "sql-instance-4",
							databaseVersion: "SQLSERVER_2019_ENTERPRISE",
							settings: {
								databaseFlags: [{ name: "contained database authentication", value: "off" }]
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

			const result = await checkSqlContainedDbAuth.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no instances exist", async () => {
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

			const result = await checkSqlContainedDbAuth.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No Cloud SQL instances found in the project");
		});

		it("should handle malformed database flags", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "sql-instance-5",
							databaseVersion: "SQLSERVER_2022_STANDARD",
							settings: {
								databaseFlags: [{ name: "contained database authentication" }] // Missing value
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

			const result = await checkSqlContainedDbAuth.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});

		it("should handle undefined settings", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "sql-instance-5",
							databaseVersion: "SQLSERVER_2022_STANDARD"
							// Missing settings
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

			const result = await checkSqlContainedDbAuth.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockList.mockImplementation(async () => {
				throw new Error("API Error");
			});

			const result = await checkSqlContainedDbAuth.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking SQL instances: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			mockList.mockImplementation(async () => {
				throw "Unknown error";
			});

			const result = await checkSqlContainedDbAuth.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking SQL instances: Unknown error");
		});

		it("should handle instances with missing required fields", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							databaseVersion: "SQLSERVER_2022_STANDARD"
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

			const result = await checkSqlContainedDbAuth.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Instance missing name or database version");
		});
	});
});
