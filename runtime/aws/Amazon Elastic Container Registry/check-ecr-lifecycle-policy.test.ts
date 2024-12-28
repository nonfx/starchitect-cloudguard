// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import {
	ECRClient,
	DescribeRepositoriesCommand,
	GetLifecyclePolicyCommand
} from "@aws-sdk/client-ecr";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkEcrLifecyclePolicyCompliance from "./check-ecr-lifecycle-policy";

const mockEcrClient = mockClient(ECRClient);

const mockRepositories = [
	{
		repositoryName: "test-repo-1",
		repositoryArn: "arn:aws:ecr:us-east-1:123456789012:repository/test-repo-1",
		registryId: "123456789012",
		createdAt: new Date()
	},
	{
		repositoryName: "test-repo-2",
		repositoryArn: "arn:aws:ecr:us-east-1:123456789012:repository/test-repo-2",
		registryId: "123456789012",
		createdAt: new Date()
	}
];

describe("checkEcrLifecyclePolicyCompliance", () => {
	beforeEach(() => {
		mockEcrClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when repositories have lifecycle policies", async () => {
			mockEcrClient.on(DescribeRepositoriesCommand).resolves({ repositories: mockRepositories });
			mockEcrClient.on(GetLifecyclePolicyCommand).resolves({ lifecyclePolicyText: "policy" });

			const result = await checkEcrLifecyclePolicyCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});

		it("should return NOTAPPLICABLE when no repositories exist", async () => {
			mockEcrClient.on(DescribeRepositoriesCommand).resolves({ repositories: [] });

			const result = await checkEcrLifecyclePolicyCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No ECR repositories found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when repositories don't have lifecycle policies", async () => {
			mockEcrClient.on(DescribeRepositoriesCommand).resolves({ repositories: mockRepositories });
			mockEcrClient
				.on(GetLifecyclePolicyCommand)
				.rejects({ name: "LifecyclePolicyNotFoundException" });

			const result = await checkEcrLifecyclePolicyCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"ECR repository does not have a lifecycle policy configured"
			);
		});

		it("should handle mixed compliance scenarios", async () => {
			mockEcrClient.on(DescribeRepositoriesCommand).resolves({ repositories: mockRepositories });
			mockEcrClient
				.on(GetLifecyclePolicyCommand)
				.resolves({ lifecyclePolicyText: "policy" })
				.on(GetLifecyclePolicyCommand, { repositoryName: "test-repo-2" })
				.rejects({ name: "LifecyclePolicyNotFoundException" });

			const result = await checkEcrLifecyclePolicyCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should handle DescribeRepositories API errors", async () => {
			mockEcrClient.on(DescribeRepositoriesCommand).rejects(new Error("API Error"));

			const result = await checkEcrLifecyclePolicyCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking ECR repositories");
		});

		it("should handle GetLifecyclePolicy API errors", async () => {
			mockEcrClient.on(DescribeRepositoriesCommand).resolves({ repositories: mockRepositories });
			mockEcrClient.on(GetLifecyclePolicyCommand).rejects(new Error("Access Denied"));

			const result = await checkEcrLifecyclePolicyCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking lifecycle policy");
		});

		it("should handle repositories without names or ARNs", async () => {
			mockEcrClient
				.on(DescribeRepositoriesCommand)
				.resolves({ repositories: [{ registryId: "123456789012" }] });

			const result = await checkEcrLifecyclePolicyCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Repository found without name or ARN");
		});
	});
});
