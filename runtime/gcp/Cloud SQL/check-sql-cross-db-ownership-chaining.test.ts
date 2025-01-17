// @ts-nocheck
import { sqladmin_v1 } from "@googleapis/sqladmin";
import { ComplianceStatus } from "../../types.js";
import { jest, describe, it, expect, beforeEach } from "@jest/globals";
import checkSqlCrossDbOwnershipChaining from "./check-sql-cross-db-ownership-chaining";

describe("checkSqlCrossDbOwnershipChaining", () => {
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
		it("should return PASS when cross db ownership chaining flag is off", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "sql-instance-1",
							databaseVersion: "SQLSERVER_2022_STANDARD",
							settings: {
								databaseFlags: [{ name: "cross db ownership chaining", value: "off" }]
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

			const result = await checkSqlCrossDbOwnershipChaining.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("sql-instance-1");
		});

		it("should return PASS when cross db ownership chaining flag is not set", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "sql-instance-1",
							databaseVersion: "SQLSERVER_2022_STANDARD",
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

			const result = await checkSqlCrossDbOwnershipChaining.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.message).toBeUndefined();
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
								databaseFlags: [{ name: "cross db ownership chaining", value: "off" }]
							}
						} as sqladmin_v1.Schema$DatabaseInstance,
						{
							name: "sql-instance-2",
							databaseVersion: "SQLSERVER_2019_ENTERPRISE",
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

			const result = await checkSqlCrossDbOwnershipChaining.execute("test-project");
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

			const result = await checkSqlCrossDbOwnershipChaining.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("Not a SQL Server instance");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when cross db ownership chaining is on", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "sql-instance-1",
							databaseVersion: "SQLSERVER_2022_STANDARD",
							settings: {
								databaseFlags: [{ name: "cross db ownership chaining", value: "on" }]
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

			const result = await checkSqlCrossDbOwnershipChaining.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"Cross db ownership chaining must be set to 'off'. To fix this, set the 'cross db ownership chaining' database flag to 'off' in the instance settings for better security. For cross-database access, use the Microsoft tutorial for signing stored procedures with a certificate. See: https://cloud.google.com/sql/docs/sqlserver/flags"
			);
		});

		it("should handle multiple instances with mixed compliance", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "sql-instance-1",
							databaseVersion: "SQLSERVER_2022_STANDARD",
							settings: {
								databaseFlags: [{ name: "cross db ownership chaining", value: "off" }]
							}
						} as sqladmin_v1.Schema$DatabaseInstance,
						{
							name: "sql-instance-2",
							databaseVersion: "SQLSERVER_2022_STANDARD",
							settings: {
								databaseFlags: [{ name: "cross db ownership chaining", value: "on" }]
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

			const result = await checkSqlCrossDbOwnershipChaining.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
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

			const result = await checkSqlCrossDbOwnershipChaining.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No Cloud SQL instances found in the project");
		});

		it("should handle undefined settings", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "sql-instance-1",
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

			const result = await checkSqlCrossDbOwnershipChaining.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockList.mockImplementation(async () => {
				throw new Error("API Error");
			});

			const result = await checkSqlCrossDbOwnershipChaining.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking SQL instances: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			mockList.mockImplementation(async () => {
				throw "Unknown error";
			});

			const result = await checkSqlCrossDbOwnershipChaining.execute("test-project");
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

			const result = await checkSqlCrossDbOwnershipChaining.execute("test-project");
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Instance missing name or database version");
		});
	});
});
