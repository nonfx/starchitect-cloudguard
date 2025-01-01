// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { AccessAnalyzerClient, ListAnalyzersCommand } from "@aws-sdk/client-accessanalyzer";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkAccessAnalyzerEnabled from "./aws_iam_access_analyzer";

const mockAccessAnalyzerClient = mockClient(AccessAnalyzerClient);

const mockActiveAnalyzer = {
	arn: "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/test-analyzer",
	name: "test-analyzer",
	status: "ACTIVE",
	type: "ACCOUNT"
};

describe("checkAccessAnalyzerEnabled", () => {
	beforeEach(() => {
		mockAccessAnalyzerClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when active analyzer exists", async () => {
			mockAccessAnalyzerClient.on(ListAnalyzersCommand).resolves({
				analyzers: [mockActiveAnalyzer]
			});

			const result = await checkAccessAnalyzerEnabled.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-analyzer");
			expect(result.checks[0].resourceArn).toBe(mockActiveAnalyzer.arn);
		});

		it("should handle multiple active analyzers", async () => {
			const secondAnalyzer = {
				...mockActiveAnalyzer,
				name: "test-analyzer-2",
				arn: "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/test-analyzer-2"
			};

			mockAccessAnalyzerClient.on(ListAnalyzersCommand).resolves({
				analyzers: [mockActiveAnalyzer, secondAnalyzer]
			});

			const result = await checkAccessAnalyzerEnabled.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no active analyzers exist", async () => {
			mockAccessAnalyzerClient.on(ListAnalyzersCommand).resolves({
				analyzers: []
			});

			const result = await checkAccessAnalyzerEnabled.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No active IAM Access Analyzer found in the region");
		});

		it("should return FAIL when only inactive analyzers exist", async () => {
			const inactiveAnalyzer = { ...mockActiveAnalyzer, status: "INACTIVE" };
			mockAccessAnalyzerClient.on(ListAnalyzersCommand).resolves({
				analyzers: [inactiveAnalyzer]
			});

			const result = await checkAccessAnalyzerEnabled.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});

		it("should return ERROR for analyzer without ARN", async () => {
			const analyzerWithoutArn = { ...mockActiveAnalyzer, arn: undefined };
			mockAccessAnalyzerClient.on(ListAnalyzersCommand).resolves({
				analyzers: [analyzerWithoutArn]
			});

			const result = await checkAccessAnalyzerEnabled.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Analyzer found without ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockAccessAnalyzerClient.on(ListAnalyzersCommand).rejects(new Error("API Error"));

			const result = await checkAccessAnalyzerEnabled.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking Access Analyzer: API Error");
		});

		it("should handle undefined analyzers response", async () => {
			mockAccessAnalyzerClient.on(ListAnalyzersCommand).resolves({});

			const result = await checkAccessAnalyzerEnabled.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});
});
