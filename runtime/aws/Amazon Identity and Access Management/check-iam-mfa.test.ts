// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import {
	IAMClient,
	ListUsersCommand,
	GetLoginProfileCommand,
	ListMFADevicesCommand
} from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkIamMfa from "./check-iam-mfa";

const mockIAMClient = mockClient(IAMClient);

const mockUsers = [
	{
		UserName: "user-with-mfa",
		Arn: "arn:aws:iam::123456789012:user/user-with-mfa",
		CreateDate: new Date()
	},
	{
		UserName: "user-without-mfa",
		Arn: "arn:aws:iam::123456789012:user/user-without-mfa",
		CreateDate: new Date()
	},
	{
		UserName: "user-no-console",
		Arn: "arn:aws:iam::123456789012:user/user-no-console",
		CreateDate: new Date()
	}
];

describe("checkIamMfa", () => {
	beforeEach(() => {
		mockIAMClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for user with console access and MFA enabled", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: [mockUsers[0]] });
			mockIAMClient.on(GetLoginProfileCommand).resolves({});
			mockIAMClient
				.on(ListMFADevicesCommand)
				.resolves({ MFADevices: [{ SerialNumber: "mfa-device" }] });

			const result = await checkIamMfa.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("user-with-mfa");
		});

		it("should return PASS for user without console access", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: [mockUsers[2]] });
			mockIAMClient.on(GetLoginProfileCommand).rejects({ name: "NoSuchEntity" });
			mockIAMClient.on(ListMFADevicesCommand).resolves({ MFADevices: [] });

			const result = await checkIamMfa.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toBe("User does not have console access");
		});

		it("should return NOTAPPLICABLE when no users exist", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: [] });

			const result = await checkIamMfa.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No IAM users found in the account");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for user with console access but no MFA", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: [mockUsers[1]] });
			mockIAMClient.on(GetLoginProfileCommand).resolves({});
			mockIAMClient.on(ListMFADevicesCommand).resolves({ MFADevices: [] });

			const result = await checkIamMfa.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("User has console access but no MFA device configured");
		});

		it("should handle multiple users with mixed compliance", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: mockUsers });
			mockIAMClient
				.on(GetLoginProfileCommand, { UserName: "user-with-mfa" })
				.resolves({})
				.on(GetLoginProfileCommand, { UserName: "user-without-mfa" })
				.resolves({})
				.on(GetLoginProfileCommand, { UserName: "user-no-console" })
				.rejects({ name: "NoSuchEntity" });
			mockIAMClient
				.on(ListMFADevicesCommand, { UserName: "user-with-mfa" })
				.resolves({ MFADevices: [{ SerialNumber: "mfa-device" }] })
				.on(ListMFADevicesCommand, { UserName: "user-without-mfa" })
				.resolves({ MFADevices: [] })
				.on(ListMFADevicesCommand, { UserName: "user-no-console" })
				.resolves({ MFADevices: [] });

			const result = await checkIamMfa.execute();
			expect(result.checks).toHaveLength(3);
			expect(result.checks.map(check => check.status)).toEqual([
				ComplianceStatus.PASS,
				ComplianceStatus.FAIL,
				ComplianceStatus.PASS
			]);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListUsers fails", async () => {
			mockIAMClient.on(ListUsersCommand).rejects(new Error("API Error"));

			const result = await checkIamMfa.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking IAM users");
		});

		it("should return ERROR for specific user when GetLoginProfile fails unexpectedly", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: [mockUsers[0]] });
			mockIAMClient.on(GetLoginProfileCommand).rejects(new Error("Access Denied"));

			const result = await checkIamMfa.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking user MFA status");
		});

		it("should return ERROR for specific user when ListMFADevices fails", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: [mockUsers[0]] });
			mockIAMClient.on(GetLoginProfileCommand).resolves({});
			mockIAMClient.on(ListMFADevicesCommand).rejects(new Error("Access Denied"));

			const result = await checkIamMfa.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking user MFA status");
		});
	});
});
