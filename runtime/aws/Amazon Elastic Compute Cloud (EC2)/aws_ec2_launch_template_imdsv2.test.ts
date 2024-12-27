// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import {
	EC2Client,
	DescribeLaunchTemplatesCommand,
	DescribeLaunchTemplateVersionsCommand
} from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types";
import checkEc2LaunchTemplateImdsv2Compliance from "./aws_ec2_launch_template_imdsv2";

const mockEC2Client = mockClient(EC2Client);

const mockLaunchTemplate = {
	LaunchTemplateId: "lt-1234567890abcdef0",
	LaunchTemplateName: "test-template",
	CreateTime: new Date(),
	CreatedBy: "arn:aws:iam::123456789012:user/test-user",
	DefaultVersionNumber: 1,
	LatestVersionNumber: 1
};

describe("checkEc2LaunchTemplateImdsv2Compliance", () => {
	beforeEach(() => {
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when IMDSv2 is required", async () => {
			mockEC2Client
				.on(DescribeLaunchTemplatesCommand)
				.resolves({ LaunchTemplates: [mockLaunchTemplate] });

			mockEC2Client.on(DescribeLaunchTemplateVersionsCommand).resolves({
				LaunchTemplateVersions: [
					{
						LaunchTemplateData: {
							MetadataOptions: {
								HttpTokens: "required"
							}
						}
					}
				]
			});

			const result = await checkEc2LaunchTemplateImdsv2Compliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-template");
		});

		it("should return NOTAPPLICABLE when no launch templates exist", async () => {
			mockEC2Client.on(DescribeLaunchTemplatesCommand).resolves({ LaunchTemplates: [] });

			const result = await checkEc2LaunchTemplateImdsv2Compliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No EC2 launch templates found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when IMDSv2 is optional", async () => {
			mockEC2Client
				.on(DescribeLaunchTemplatesCommand)
				.resolves({ LaunchTemplates: [mockLaunchTemplate] });

			mockEC2Client.on(DescribeLaunchTemplateVersionsCommand).resolves({
				LaunchTemplateVersions: [
					{
						LaunchTemplateData: {
							MetadataOptions: {
								HttpTokens: "optional"
							}
						}
					}
				]
			});

			const result = await checkEc2LaunchTemplateImdsv2Compliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("does not require IMDSv2");
		});

		it("should return FAIL when MetadataOptions is not set", async () => {
			mockEC2Client
				.on(DescribeLaunchTemplatesCommand)
				.resolves({ LaunchTemplates: [mockLaunchTemplate] });

			mockEC2Client.on(DescribeLaunchTemplateVersionsCommand).resolves({
				LaunchTemplateVersions: [
					{
						LaunchTemplateData: {}
					}
				]
			});

			const result = await checkEc2LaunchTemplateImdsv2Compliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when DescribeLaunchTemplates fails", async () => {
			mockEC2Client.on(DescribeLaunchTemplatesCommand).rejects(new Error("API Error"));

			const result = await checkEc2LaunchTemplateImdsv2Compliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking launch templates");
		});

		it("should return ERROR when DescribeLaunchTemplateVersions fails", async () => {
			mockEC2Client
				.on(DescribeLaunchTemplatesCommand)
				.resolves({ LaunchTemplates: [mockLaunchTemplate] });

			mockEC2Client
				.on(DescribeLaunchTemplateVersionsCommand)
				.rejects(new Error("Version API Error"));

			const result = await checkEc2LaunchTemplateImdsv2Compliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking launch template version");
		});

		it("should handle missing template data", async () => {
			mockEC2Client
				.on(DescribeLaunchTemplatesCommand)
				.resolves({ LaunchTemplates: [mockLaunchTemplate] });

			mockEC2Client.on(DescribeLaunchTemplateVersionsCommand).resolves({
				LaunchTemplateVersions: [{}]
			});

			const result = await checkEc2LaunchTemplateImdsv2Compliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Unable to retrieve launch template data");
		});
	});

	describe("Multiple Resources", () => {
		it("should handle multiple launch templates with different configurations", async () => {
			const templates = [
				{ ...mockLaunchTemplate, LaunchTemplateId: "lt-1", LaunchTemplateName: "template-1" },
				{ ...mockLaunchTemplate, LaunchTemplateId: "lt-2", LaunchTemplateName: "template-2" }
			];

			mockEC2Client.on(DescribeLaunchTemplatesCommand).resolves({ LaunchTemplates: templates });

			mockEC2Client
				.on(DescribeLaunchTemplateVersionsCommand, { LaunchTemplateId: "lt-1" })
				.resolves({
					LaunchTemplateVersions: [
						{
							LaunchTemplateData: {
								MetadataOptions: { HttpTokens: "required" }
							}
						}
					]
				})
				.on(DescribeLaunchTemplateVersionsCommand, { LaunchTemplateId: "lt-2" })
				.resolves({
					LaunchTemplateVersions: [
						{
							LaunchTemplateData: {
								MetadataOptions: { HttpTokens: "optional" }
							}
						}
					]
				});

			const result = await checkEc2LaunchTemplateImdsv2Compliance.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});
});
