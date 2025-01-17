// @ts-nocheck
import { sqladmin_v1 } from "@googleapis/sqladmin";
import { ComplianceStatus } from "../../types.js";
import { jest, describe, it, expect, beforeEach } from "@jest/globals";
import checkCloudSqlLocalInfileFlag from "./check-cloud-sql-local-infile";

describe("checkCloudSqlLocalInfileFlag", () => {
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
		it("should return PASS when local_infile flag is set to off", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "mysql-instance-1",
							databaseVersion: "MYSQL_8_0",
							settings: {
								databaseFlags: [{ name: "local_infile", value: "off" }]
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

			const result = await checkCloudSqlLocalInfileFlag.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("mysql-instance-1");
		});

		it("should return NOTAPPLICABLE for non-MySQL instances", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "postgres-instance",
							databaseVersion: "POSTGRES_13",
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

			const result = await checkCloudSqlLocalInfileFlag.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("Not a MySQL instance");
		});

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

			const result = await checkCloudSqlLocalInfileFlag.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No Cloud SQL instances found in the project");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when local_infile flag is set to on", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "mysql-instance-2",
							databaseVersion: "MYSQL_8_0",
							settings: {
								databaseFlags: [{ name: "local_infile", value: "on" }]
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

			const result = await checkCloudSqlLocalInfileFlag.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"local_infile flag is not set to 'off'. To fix this, set the local_infile database flag to 'off' in the instance settings. See: https://cloud.google.com/sql/docs/mysql/flags#setting_a_database_flag"
			);
		});

		it("should return FAIL when local_infile flag is missing", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "mysql-instance-3",
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

			const result = await checkCloudSqlLocalInfileFlag.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"local_infile flag is not set to 'off'. To fix this, set the local_infile database flag to 'off' in the instance settings. See: https://cloud.google.com/sql/docs/mysql/flags#setting_a_database_flag"
			);
		});

		it("should handle multiple instances with mixed compliance", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "mysql-compliant",
							databaseVersion: "MYSQL_8_0",
							settings: {
								databaseFlags: [{ name: "local_infile", value: "off" }]
							}
						} as sqladmin_v1.Schema$DatabaseInstance,
						{
							name: "mysql-non-compliant",
							databaseVersion: "MYSQL_8_0",
							settings: {
								databaseFlags: [{ name: "local_infile", value: "on" }]
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

			const result = await checkCloudSqlLocalInfileFlag.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should handle malformed database flags", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "mysql-instance-4",
							databaseVersion: "MYSQL_8_0",
							settings: {
								databaseFlags: [{ name: "local_infile" }] // Missing value
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

			const result = await checkCloudSqlLocalInfileFlag.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"local_infile flag is not set to 'off'. To fix this, set the local_infile database flag to 'off' in the instance settings. See: https://cloud.google.com/sql/docs/mysql/flags#setting_a_database_flag"
			);
		});

		it("should handle undefined settings", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							name: "mysql-instance-5",
							databaseVersion: "MYSQL_8_0"
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

			const result = await checkCloudSqlLocalInfileFlag.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"local_infile flag is not set to 'off'. To fix this, set the local_infile database flag to 'off' in the instance settings. See: https://cloud.google.com/sql/docs/mysql/flags#setting_a_database_flag"
			);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockList.mockImplementation(async () => {
				throw new Error("API Error");
			});

			const result = await checkCloudSqlLocalInfileFlag.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking Cloud SQL instances: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			mockList.mockImplementation(async () => {
				throw "Unknown error";
			});

			const result = await checkCloudSqlLocalInfileFlag.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking Cloud SQL instances: Unknown error");
		});

		it("should handle instances with missing required fields", async () => {
			mockList.mockImplementation(async () => ({
				data: {
					kind: "sql#instancesList",
					items: [
						{
							databaseVersion: "MYSQL_8_0"
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

			const result = await checkCloudSqlLocalInfileFlag.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Instance missing name or database version");
		});
	});
});
