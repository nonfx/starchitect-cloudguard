import { IAMClient, ListUsersCommand, ListSAMLProvidersCommand } from "@aws-sdk/client-iam";
import { OrganizationsClient, DescribeOrganizationCommand } from "@aws-sdk/client-organizations";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "@codegen/utils/stringUtils";
import checkIamCentralizedManagement from "./aws_iam_centralized_management";

const mockIAMClient = mockClient(IAMClient);
const mockOrganizationsClient = mockClient(OrganizationsClient);

describe("checkIamCentralizedManagement", () => {
	beforeEach(() => {
		mockIAMClient.reset();
		mockOrganizationsClient.reset();
	});

	it("should return ERROR when no IAM users exist", async () => {
		mockIAMClient.on(ListUsersCommand).resolves({ Users: [] });

		const result = await checkIamCentralizedManagement();
		expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
		expect(result.checks[0].message).toBe("No IAM users found in the account");
	});

	it("should return PASS when IAM users exist with SAML", async () => {
		mockIAMClient
			.on(ListUsersCommand)
			.resolves({ Users: [{ UserName: "test-user" }] })
			.on(ListSAMLProvidersCommand)
			.resolves({ SAMLProviderList: [{ Arn: "arn:aws:iam::123456789012:saml-provider/test" }] });
		mockOrganizationsClient
			.on(DescribeOrganizationCommand)
			.rejects({ name: "AccessDeniedException" });

		const result = await checkIamCentralizedManagement();
		expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		expect(result.checks[0].message).toContain("SAML federation");
	});

	it("should return PASS when IAM users exist with Organizations", async () => {
		mockIAMClient
			.on(ListUsersCommand)
			.resolves({ Users: [{ UserName: "test-user" }] })
			.on(ListSAMLProvidersCommand)
			.resolves({ SAMLProviderList: [] });
		mockOrganizationsClient
			.on(DescribeOrganizationCommand)
			.resolves({ Organization: { Id: "o-123456" } });

		const result = await checkIamCentralizedManagement();
		expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		expect(result.checks[0].message).toContain("AWS Organizations");
	});

	it("should return FAIL when IAM users exist without central management", async () => {
		mockIAMClient
			.on(ListUsersCommand)
			.resolves({ Users: [{ UserName: "test-user" }] })
			.on(ListSAMLProvidersCommand)
			.resolves({ SAMLProviderList: [] });
		mockOrganizationsClient
			.on(DescribeOrganizationCommand)
			.rejects({ name: "AccessDeniedException" });

		const result = await checkIamCentralizedManagement();
		expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		expect(result.checks[0].message).toContain("not managed centrally");
	});

	it("should return ERROR when IAM API fails", async () => {
		mockIAMClient.on(ListUsersCommand).rejects(new Error("IAM API Error"));

		const result = await checkIamCentralizedManagement();
		expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
		expect(result.checks[0].message).toContain("IAM API Error");
	});
});
