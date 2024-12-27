// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import {
	EC2Client,
	DescribeLaunchTemplatesCommand,
	DescribeLaunchTemplateVersionsCommand
} from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types";
import checkLaunchTemplatePublicIp from "./aws_ec2_launch_template_public_ip";

const mockEC2Client = mockClient(EC2Client);

const mockLaunchTemplate = {
	LaunchTemplateId: "lt-1234567890abcdef0",
	LaunchTemplateName: "test-template",
	CreateTime: new Date(),
	CreatedBy: "arn:aws:iam::123456789012:user/test-user",
	DefaultVersionNumber: 1,
	LatestVersionNumber: 1
};

describe("checkLaunchTemplatePublicIp", () => {
	beforeEach(() => {
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when launch template does not assign public IPs", async () => {
			mockEC2Client
				.on(DescribeLaunchTemplatesCommand)
				.resolves({ LaunchTemplates: [mockLaunchTemplate] });

			mockEC2Client.on(DescribeLaunchTemplateVersionsCommand).resolves({
				LaunchTemplateVersions: [
					{
						LaunchTemplateData: {
							NetworkInterfaces: [{ AssociatePublicIpAddress: false }]
						}
					}
				]
			});

			const result = await checkLaunchTemplatePublicIp.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-template");
		});

		it("should return NOTAPPLICABLE when no launch templates exist", async () => {
			mockEC2Client.on(DescribeLaunchTemplatesCommand).resolves({ LaunchTemplates: [] });

			const result = await checkLaunchTemplatePublicIp.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No EC2 launch templates found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when launch template assigns public IPs", async () => {
			mockEC2Client
				.on(DescribeLaunchTemplatesCommand)
				.resolves({ LaunchTemplates: [mockLaunchTemplate] });

			mockEC2Client.on(DescribeLaunchTemplateVersionsCommand).resolves({
				LaunchTemplateVersions: [
					{
						LaunchTemplateData: {
							NetworkInterfaces: [{ AssociatePublicIpAddress: true }]
						}
					}
				]
			});

			const result = await checkLaunchTemplatePublicIp.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Launch template assigns public IP addresses to network interfaces"
			);
		});

		it("should handle multiple network interfaces with mixed configurations", async () => {
			mockEC2Client
				.on(DescribeLaunchTemplatesCommand)
				.resolves({ LaunchTemplates: [mockLaunchTemplate] });

			mockEC2Client.on(DescribeLaunchTemplateVersionsCommand).resolves({
				LaunchTemplateVersions: [
					{
						LaunchTemplateData: {
							NetworkInterfaces: [
								{ AssociatePublicIpAddress: false },
								{ AssociatePublicIpAddress: true }
							]
						}
					}
				]
			});

			const result = await checkLaunchTemplatePublicIp.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when DescribeLaunchTemplates fails", async () => {
			mockEC2Client.on(DescribeLaunchTemplatesCommand).rejects(new Error("API Error"));

			const result = await checkLaunchTemplatePublicIp.execute("us-east-1");
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

			const result = await checkLaunchTemplatePublicIp.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking launch template version");
		});

		it("should handle launch templates without ID or name", async () => {
			mockEC2Client.on(DescribeLaunchTemplatesCommand).resolves({ LaunchTemplates: [{}] });

			const result = await checkLaunchTemplatePublicIp.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Launch template found without ID or name");
		});
	});
});
