// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { ECRClient, DescribeRepositoriesCommand } from "@aws-sdk/client-ecr";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types";
import checkEcrTagImmutability from "./check-ecr-tag-immutability";

const mockEcrClient = mockClient(ECRClient);

const mockRepositories = [
	{
		repositoryName: "test-repo-1",
		repositoryArn: "arn:aws:ecr:us-east-1:123456789012:repository/test-repo-1",
		imageTagMutability: "IMMUTABLE"
	},
	{
		repositoryName: "test-repo-2",
		repositoryArn: "arn:aws:ecr:us-east-1:123456789012:repository/test-repo-2",
		imageTagMutability: "MUTABLE"
	}
];

describe("checkEcrTagImmutability", () => {
	beforeEach(() => {
		mockEcrClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when repository has immutable tags", async () => {
			mockEcrClient.on(DescribeRepositoriesCommand).resolves({
				repositories: [mockRepositories[0]]
			});

			const result = await checkEcrTagImmutability.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-repo-1");
			expect(result.checks[0].resourceArn).toBe(mockRepositories[0].repositoryArn);
		});

		it("should return NOTAPPLICABLE when no repositories exist", async () => {
			mockEcrClient.on(DescribeRepositoriesCommand).resolves({
				repositories: []
			});

			const result = await checkEcrTagImmutability.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No ECR repositories found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when repository has mutable tags", async () => {
			mockEcrClient.on(DescribeRepositoriesCommand).resolves({
				repositories: [mockRepositories[1]]
			});

			const result = await checkEcrTagImmutability.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"ECR repository does not have tag immutability enabled"
			);
		});

		it("should handle mixed compliance states", async () => {
			mockEcrClient.on(DescribeRepositoriesCommand).resolves({
				repositories: mockRepositories
			});

			const result = await checkEcrTagImmutability.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle repositories with missing data", async () => {
			mockEcrClient.on(DescribeRepositoriesCommand).resolves({
				repositories: [{ imageTagMutability: "IMMUTABLE" }]
			});

			const result = await checkEcrTagImmutability.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Repository found without name or ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockEcrClient
				.on(DescribeRepositoriesCommand)
				.rejects(new Error("Failed to describe repositories"));

			const result = await checkEcrTagImmutability.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking ECR repositories");
		});

		it("should handle pagination", async () => {
			mockEcrClient
				.on(DescribeRepositoriesCommand)
				.resolvesOnce({
					repositories: [mockRepositories[0]],
					nextToken: "token1"
				})
				.resolvesOnce({
					repositories: [mockRepositories[1]]
				});

			const result = await checkEcrTagImmutability.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});
});
